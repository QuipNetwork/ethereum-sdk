// Step 1 in the test-sdk operator flow.
//
// What this script does, in order:
//   1. If wallet 2's EOA has 0 ETH on chain, transfer
//      `WALLET_2_FUND_AMOUNT_WEI` from wallet 1 to wallet 2. Just enough
//      for wallet 2 to pay gas for its own QuipWallet creation tx.
//   2. For each of (wallet 1, wallet 2):
//        a. Query `factory.quips(eoa, vaultId)`. If non-zero, the Quip
//           wallet is already deployed for this (eoa, vaultId) pair —
//           skip and log the existing address.
//        b. Otherwise: derive the WOTS+ keyset (1 disaster + 1 ownership
//           + 5 transaction + 10 recovery keys) from this EOA's
//           hardcoded `quantumSecret + vaultId`, ABI-pack into the init
//           payload, and call
//             factory.deployLatestWalletProxy(vaultId, eoa, initPayload)
//           via the EOA's wallet client. The factory picks
//           `latestWalletImpl` automatically (the impl we vetted in
//           `make vet-impl-op-sepolia`).
//        c. Parse `QuipCreated` from the receipt and log the new address.
//
// Idempotent: re-running after a successful first run is a no-op except
// for one ETH balance check on wallet 2 and two factory `quips(...)`
// reads.
import {
  formatEther,
  parseEventLogs,
  type Address,
  type Hex,
  type TransactionReceipt,
} from "viem";

import {
  CHAIN_ID,
  QUIP_FACTORY,
  WALLET_1_ADDRESS,
  WALLET_1_PRIVATE_KEY,
  WALLET_1_QUANTUM_SECRET,
  WALLET_1_VAULT_ID,
  WALLET_2_ADDRESS,
  WALLET_2_FUND_AMOUNT_WEI,
  WALLET_2_PRIVATE_KEY,
  WALLET_2_QUANTUM_SECRET,
  WALLET_2_VAULT_ID,
} from "./config.js";
import { makeClients, type EoaClients } from "./clients.js";

import { quipFactoryAbi } from "../src/v1/abi/QuipFactory.js";
import { QuipSigner } from "../src/v1/signer.js";
import {
  encodeInit,
  RECOVERY_KEY_AMOUNT,
  TRANSACTION_KEY_INIT_AMOUNT,
  type WinternitzAddress,
} from "../src/v1/wotsCodec.js";

const ZERO_ADDRESS: Address = "0x0000000000000000000000000000000000000000";

async function main(): Promise<void> {
  console.log("=== test-sdk / createWallets ===");
  console.log(`Chain: OP Sepolia (${CHAIN_ID})`);
  console.log(`Factory: ${QUIP_FACTORY}`);
  console.log("");

  const w1 = makeClients({
    privateKey: WALLET_1_PRIVATE_KEY,
    expectedAddress: WALLET_1_ADDRESS,
    quantumSecret: WALLET_1_QUANTUM_SECRET,
  });
  const w2 = makeClients({
    privateKey: WALLET_2_PRIVATE_KEY,
    expectedAddress: WALLET_2_ADDRESS,
    quantumSecret: WALLET_2_QUANTUM_SECRET,
  });

  // -------------------------------------------------------------------
  // 1. Fund wallet 2 if empty.
  // -------------------------------------------------------------------
  await fundWallet2IfNeeded(w1, w2);

  // -------------------------------------------------------------------
  // 2. Create Quip wallets (idempotent).
  // -------------------------------------------------------------------
  const w1Quip = await ensureQuipWallet({
    label: "wallet-1",
    clients: w1,
    vaultId: WALLET_1_VAULT_ID,
  });
  const w2Quip = await ensureQuipWallet({
    label: "wallet-2",
    clients: w2,
    vaultId: WALLET_2_VAULT_ID,
  });

  console.log("");
  console.log("=== Summary ===");
  console.log(`wallet-1 EOA:  ${w1.address}  →  Quip wallet: ${w1Quip}`);
  console.log(`wallet-2 EOA:  ${w2.address}  →  Quip wallet: ${w2Quip}`);
  console.log("");
  console.log("Next: npx tsx test-sdk/transferERC20.ts");
}

/**
 * One-time funding step. Reads wallet 2's on-chain balance and, if 0,
 * sends `WALLET_2_FUND_AMOUNT_WEI` from wallet 1 to wallet 2. No-op on
 * re-runs once wallet 2 has any positive balance.
 */
async function fundWallet2IfNeeded(
  w1: EoaClients,
  w2: EoaClients
): Promise<void> {
  const balance = await w1.publicClient.getBalance({ address: w2.address });
  console.log(`wallet-2 balance: ${formatEther(balance)} ETH`);
  if (balance > 0n) {
    console.log("  → already funded, skipping transfer");
    return;
  }

  const w1Balance = await w1.publicClient.getBalance({ address: w1.address });
  if (w1Balance < WALLET_2_FUND_AMOUNT_WEI) {
    throw new Error(
      `wallet-1 has ${formatEther(w1Balance)} ETH but needs at least ` +
        `${formatEther(WALLET_2_FUND_AMOUNT_WEI)} ETH to fund wallet-2.`
    );
  }

  console.log(
    `  → funding wallet-2 with ${formatEther(WALLET_2_FUND_AMOUNT_WEI)} ETH ` +
      `from wallet-1...`
  );
  const hash = await w1.walletClient.sendTransaction({
    account: w1.walletClient.account!,
    chain: w1.walletClient.chain,
    to: w2.address,
    value: WALLET_2_FUND_AMOUNT_WEI,
  });
  console.log(`  → funding tx: ${hash}`);
  const receipt = await w1.publicClient.waitForTransactionReceipt({ hash });
  console.log(`  → funded in block ${receipt.blockNumber}`);
}

/**
 * Return the Quip wallet address for `(clients.address, vaultId)`,
 * deploying it via `factory.deployLatestWalletProxy` if missing.
 */
async function ensureQuipWallet(params: {
  label: string;
  clients: EoaClients;
  vaultId: Hex;
}): Promise<Address> {
  const { label, clients, vaultId } = params;
  console.log("");
  console.log(`--- ${label} (${clients.address}) ---`);

  const existing = (await clients.publicClient.readContract({
    address: QUIP_FACTORY,
    abi: quipFactoryAbi,
    functionName: "quips",
    args: [clients.address, vaultId],
  })) as Address;

  if (existing.toLowerCase() !== ZERO_ADDRESS.toLowerCase()) {
    console.log(`  Quip wallet already exists: ${existing}`);
    return existing;
  }

  console.log(`  no existing wallet — generating keys + deploying...`);

  // Generate the full initial keyset: 1 disaster + 1 ownership + 5
  // transaction + 10 recovery. All derived from `(quantumSecret, vaultId)`
  // with cryptographically random `publicSeed`s.
  const disasterKey = clients.quipSigner.generateKeyPair(vaultId).publicKey;
  const ownershipKey = clients.quipSigner.generateKeyPair(vaultId).publicKey;
  const transactionKeys: WinternitzAddress[] = Array.from(
    { length: TRANSACTION_KEY_INIT_AMOUNT },
    () => clients.quipSigner.generateKeyPair(vaultId).publicKey
  );
  const recoveryKeys: WinternitzAddress[] = Array.from(
    { length: RECOVERY_KEY_AMOUNT },
    () => clients.quipSigner.generateKeyPair(vaultId).publicKey
  );
  const initPayload = encodeInit(
    disasterKey,
    ownershipKey,
    transactionKeys,
    recoveryKeys
  );
  console.log(
    `  init payload: ${initPayload.length / 2 - 1} bytes (1 disaster + 1 ` +
      `ownership + ${TRANSACTION_KEY_INIT_AMOUNT} tx + ${RECOVERY_KEY_AMOUNT} ` +
      `recovery WOTS+ keys)`
  );

  const hash = await clients.walletClient.writeContract({
    account: clients.walletClient.account!,
    chain: clients.walletClient.chain,
    address: QUIP_FACTORY,
    abi: quipFactoryAbi,
    functionName: "deployLatestWalletProxy",
    args: [vaultId, clients.address, initPayload],
  });
  console.log(`  deploy tx: ${hash}`);

  const receipt: TransactionReceipt =
    await clients.publicClient.waitForTransactionReceipt({ hash });

  const events = parseEventLogs({
    abi: quipFactoryAbi,
    logs: receipt.logs,
    eventName: "QuipCreated",
  });
  if (events.length === 0) {
    throw new Error("deployLatestWalletProxy succeeded but no QuipCreated event found");
  }
  const walletAddress = events[0].args.quip as Address;
  console.log(`  → Quip wallet deployed at: ${walletAddress}`);
  console.log(`  → gas used: ${receipt.gasUsed}`);
  return walletAddress;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

// Reference imports kept to assert the module surface compiles cleanly
// against the live SDK source. Removing these breaks no behavior; they
// just ensure CI / `tsc` catches a removed export in the SDK.
void QuipSigner;
