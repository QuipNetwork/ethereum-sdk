// Step 2 in the test-sdk operator flow.
//
// What this script does, in order:
//   1. Load both Quip wallet addresses from the factory (must have been
//      deployed first via `createWallets.ts`).
//   2. Read wallet 1's Quip wallet tQ6 balance. If below
//      `TRANSFER_AMOUNT_TQ6`, mint `TQ6_TOPUP_AMOUNT` directly to it
//      via the dummy ERC20's permissionless `mint(to, amount)` — this
//      tx is signed by wallet 1's EOA (gas payer), the recipient is the
//      Quip wallet.
//   3. Build calldata for `tQ6.transfer(wallet2QuipAddress, 10 * 10**6)`.
//   4. Call `wallet1QuipClient.executeWithPayload(tQ6, 0n, calldata)` —
//      this is the SDK method that:
//        a. Reads the wallet's current `executeFee()` (0 right now)
//        b. Picks the head transaction key + the next key
//        c. Builds the execute digest (`executeDigest(...)`)
//        d. Signs the digest with the head key's private WOTS+ material
//           (one-time-use: the head key is BURNED here, the wallet
//           rotates to the next key on the next call)
//        e. Encodes the full payload: currentKey + nextKey + WOTS+ sig +
//           target + value + data
//        f. Submits `wallet.execute(payload)` as a normal EOA tx — wallet
//           1's EOA pays gas, the WOTS+ signature inside `payload`
//           authorizes the wallet to make the inner transfer call.
//   5. Verify wallet 2's Quip wallet tQ6 balance increased by exactly
//      `TRANSFER_AMOUNT_TQ6`.
//
// Re-runnable: each successful run rotates the wallet's transaction key
// on-chain, so the next run picks up the new head key automatically (the
// SDK's `getHeadTransactionKey()` reads from chain). The dummy ERC20 has
// permissionless mint, so wallet 1's Quip wallet can be topped up
// indefinitely.
import {
  encodeFunctionData,
  formatUnits,
  type Address,
  type Hex,
} from "viem";

import {
  CHAIN_ID,
  ERC20_ABI,
  QUIP_FACTORY,
  TQ6,
  TQ6_DECIMALS,
  TQ6_TOPUP_AMOUNT,
  TRANSFER_AMOUNT_TQ6,
  WALLET_1_ADDRESS,
  WALLET_1_PRIVATE_KEY,
  WALLET_1_QUANTUM_SECRET,
  WALLET_1_VAULT_ID,
  WALLET_2_ADDRESS,
  WALLET_2_PRIVATE_KEY,
  WALLET_2_QUANTUM_SECRET,
  WALLET_2_VAULT_ID,
} from "./config.js";
import { makeClients, type EoaClients } from "./clients.js";

import { quipFactoryAbi } from "../src/v1/abi/QuipFactory.js";
import { QuipWalletClient } from "../src/v1/walletClient.js";

const ZERO_ADDRESS: Address = "0x0000000000000000000000000000000000000000";

async function main(): Promise<void> {
  console.log("=== test-sdk / transferERC20 ===");
  console.log(`Chain: OP Sepolia (${CHAIN_ID})`);
  console.log(`tQ6:   ${TQ6}`);
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
  // 1. Resolve both Quip wallet addresses (must exist).
  // -------------------------------------------------------------------
  const w1Quip = await loadQuipWallet(w1, WALLET_1_VAULT_ID, "wallet-1");
  const w2Quip = await loadQuipWallet(w2, WALLET_2_VAULT_ID, "wallet-2");

  // -------------------------------------------------------------------
  // 2. Top up wallet 1's Quip wallet with tQ6 if it's low.
  // -------------------------------------------------------------------
  await topUpTQ6IfNeeded(w1, w1Quip);

  // -------------------------------------------------------------------
  // 3+4. Build the transfer calldata + execute via the SDK.
  // -------------------------------------------------------------------
  const before = {
    sender: await readBalance(w1, w1Quip),
    recipient: await readBalance(w1, w2Quip),
  };
  console.log("");
  console.log(`Before:`);
  console.log(`  wallet-1 Quip (${w1Quip}) tQ6: ${fmtTQ6(before.sender)}`);
  console.log(`  wallet-2 Quip (${w2Quip}) tQ6: ${fmtTQ6(before.recipient)}`);

  const transferCalldata = encodeFunctionData({
    abi: ERC20_ABI,
    functionName: "transfer",
    args: [w2Quip, TRANSFER_AMOUNT_TQ6],
  });

  // Build a QuipWalletClient bound to wallet 1's Quip wallet, signing
  // with wallet 1's quantumSecret-derived signer. The factory's
  // `latestWalletImpl` (vetted in `make vet-impl-op-sepolia`) is what
  // sits behind the ERC1967 proxy at `w1Quip` — no need to specify it
  // here; the wallet introspects its own impl.
  // NOTE on the `w1.account as unknown as Address` cast: the SDK's
  // constructor types this slot as `Address` (a hex string), and at
  // runtime feeds it straight into viem's `writeContract({ account })`.
  // viem accepts BOTH a hex address (JSON-RPC node-signing account) and
  // a full `Account` object (LocalAccount with in-process signing) at
  // that key. Alchemy & most hosted RPCs reject `eth_sendTransaction`,
  // so the hex-address path fails with "Unsupported method". Handing in
  // the `Account` object instead makes viem sign locally and call
  // `eth_sendRawTransaction`. The cast is a one-line ABI mismatch
  // between the SDK's narrowed TS type and viem's actual runtime
  // surface — see `test-sdk/clients.ts:EoaClients.account` for the
  // full explanation.
  const walletClient = new QuipWalletClient(
    w1.quipSigner,
    WALLET_1_VAULT_ID,
    w1Quip,
    w1.publicClient,
    w1.walletClient,
    w1.account as unknown as Address,
    CHAIN_ID
  );

  console.log("");
  console.log(`Submitting wallet.execute(...) with WOTS+ signature...`);
  console.log(`  target: ${TQ6}`);
  console.log(`  value:  0 wei`);
  console.log(`  data:   ${transferCalldata}`);

  const receipt = await walletClient.executeWithPayload(
    TQ6,
    0n,
    transferCalldata
  );
  console.log(`  → tx hash: ${receipt.transactionHash}`);
  console.log(`  → gas used: ${receipt.gasUsed}`);
  console.log(`  → status: ${receipt.status}`);

  // -------------------------------------------------------------------
  // 5. Verify the move. Pin reads to the receipt's blockNumber — hosted
  //    RPCs (Alchemy/Infura/etc.) often have a brief read-after-write
  //    inconsistency window where `eth_call` at "latest" still reflects
  //    the pre-tx state for several hundred ms after the tx mines.
  //    Reading explicitly at the receipt's block sidesteps the lag.
  // -------------------------------------------------------------------
  const after = {
    sender: await readBalance(w1, w1Quip, receipt.blockNumber),
    recipient: await readBalance(w1, w2Quip, receipt.blockNumber),
  };
  console.log("");
  console.log(`After:`);
  console.log(`  wallet-1 Quip (${w1Quip}) tQ6: ${fmtTQ6(after.sender)}`);
  console.log(`  wallet-2 Quip (${w2Quip}) tQ6: ${fmtTQ6(after.recipient)}`);

  const senderDelta = before.sender - after.sender;
  const recipientDelta = after.recipient - before.recipient;
  if (
    senderDelta !== TRANSFER_AMOUNT_TQ6 ||
    recipientDelta !== TRANSFER_AMOUNT_TQ6
  ) {
    throw new Error(
      `Balance delta mismatch: sender -${senderDelta}, recipient +${recipientDelta}, ` +
        `expected ±${TRANSFER_AMOUNT_TQ6}`
    );
  }
  console.log("");
  console.log(`Transfer succeeded: ${fmtTQ6(TRANSFER_AMOUNT_TQ6)} moved.`);

  // wallet-2 client unused for the transfer itself but kept to demonstrate
  // both signers compile + would work for reverse transfers.
  void w2;
}

async function loadQuipWallet(
  clients: EoaClients,
  vaultId: Hex,
  label: string
): Promise<Address> {
  const addr = (await clients.publicClient.readContract({
    address: QUIP_FACTORY,
    abi: quipFactoryAbi,
    functionName: "quips",
    args: [clients.address, vaultId],
  })) as Address;
  if (addr.toLowerCase() === ZERO_ADDRESS.toLowerCase()) {
    throw new Error(
      `${label}: no Quip wallet found for EOA ${clients.address} + vaultId ${vaultId}. ` +
        `Run \`npx tsx test-sdk/createWallets.ts\` first.`
    );
  }
  return addr;
}

async function topUpTQ6IfNeeded(
  funder: EoaClients,
  quipWallet: Address
): Promise<void> {
  const current = await readBalance(funder, quipWallet);
  if (current >= TRANSFER_AMOUNT_TQ6) {
    console.log(
      `tQ6 balance on wallet-1 Quip (${fmtTQ6(current)}) already ` +
        `≥ transfer amount (${fmtTQ6(TRANSFER_AMOUNT_TQ6)}); skipping mint.`
    );
    return;
  }
  console.log(
    `tQ6 balance on wallet-1 Quip (${fmtTQ6(current)}) below ` +
      `${fmtTQ6(TRANSFER_AMOUNT_TQ6)} — minting ${fmtTQ6(TQ6_TOPUP_AMOUNT)} ` +
      `directly from EOA...`
  );
  const hash = await funder.walletClient.writeContract({
    account: funder.walletClient.account!,
    chain: funder.walletClient.chain,
    address: TQ6,
    abi: ERC20_ABI,
    functionName: "mint",
    args: [quipWallet, TQ6_TOPUP_AMOUNT],
  });
  console.log(`  → mint tx: ${hash}`);
  await funder.publicClient.waitForTransactionReceipt({ hash });
}

async function readBalance(
  clients: EoaClients,
  account: Address,
  blockNumber?: bigint
): Promise<bigint> {
  return (await clients.publicClient.readContract({
    address: TQ6,
    abi: ERC20_ABI,
    functionName: "balanceOf",
    args: [account],
    ...(blockNumber !== undefined && { blockNumber }),
  })) as bigint;
}

function fmtTQ6(raw: bigint): string {
  return `${formatUnits(raw, TQ6_DECIMALS)} tQ6`;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
