// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Forked-mainnet smoke test. Pulls real chain state and the real
// canonical ERC-4337 v0.7 EntryPoint (already deployed at
// `0x0000000071727De22E5E9d8BAf0edAc6f37da032`), deploys the Quip stack
// on top, and exercises the full SDK lifecycle: factory deploy → wallet
// create → ETH transfer execute → key management → unsponsored UserOp →
// sponsored UserOp. Different from `integration.erc4337-*` because it
// runs against real chain config (chainId, gas oracle, EIP-1559 base
// fee dynamics, real EntryPoint state) instead of vanilla Anvil + a
// `setCode`-installed EntryPoint.
//
// Gated on `FORK_RPC_URL` — skipped when unset so default CI doesn't
// need network access. Recommended providers:
//   FORK_RPC_URL=https://eth.merkle.io          # public, free
//   FORK_RPC_URL=https://rpc.ankr.com/eth       # public, free
//   FORK_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/<KEY>  # rate-limited
import {
  describe,
  test,
  expect,
  beforeAll,
  afterAll,
} from "@jest/globals";
import {
  type Address,
  type Hex,
  type PublicClient,
  type TestClient,
  type WalletClient,
  createPublicClient,
  createTestClient,
  createWalletClient,
  encodeFunctionData,
  http,
  parseEther,
  parseEventLogs,
  toHex,
  zeroAddress,
} from "viem";
import { createAnvil } from "@viem/anvil";
import { mainnet } from "viem/chains";

import { quipFactoryAbi } from "../abi/QuipFactory.js";
import { quipPaymasterAbi } from "../abi/QuipPaymaster.js";
import { entryPointV07Abi } from "../abi/EntryPointV07.js";
import { CANONICAL_ENTRYPOINT_V07 } from "../addresses.js";
import { QuipSigner } from "../signer.js";
import { createInMemoryBurnSet } from "../burnSet.js";
import { WOTSPlusImplementationClient, KeyType } from "../walletClient.js";
import { QuipPaymasterClient } from "../paymasterClient.js";
import {
  parseExecutionSucceeded,
  parseKeyRotated,
  parseKeysetReset,
  parseQuipCreated,
  parseUserOpSponsored,
  parseWalletReceipt,
} from "../events.js";
import {
  encodeInit,
  type WinternitzAddress,
  MAX_KEYS,
} from "../wotsCodec.js";
import {
  DEFAULT_ACCOUNT,
  deployErc1967Proxy,
  linkBytecode,
  loadForgeArtifacts,
} from "./utils/anvilFixture.js";

const {
  factoryBytecode,
  walletArtifact,
  walletUnlinkedBytecode,
  walletAbi: wotsPlusImplementationDeployAbi,
  paymasterArtifact,
  paymasterUnlinkedBytecode,
  paymasterAbi: quipPaymasterDeployAbi,
  wotsPlusBytecode,
  wotsPlusAbi,
} = loadForgeArtifacts();

// Anvil's first prefunded dev account. `--fork-url` keeps this funded
// regardless of mainnet state.
const account = DEFAULT_ACCOUNT;

const FORK_RPC_URL = process.env.FORK_RPC_URL;
const SHOULD_RUN = !!FORK_RPC_URL;

const anvil = createAnvil({
  port: 8556,
  // Forking a real RPC takes much longer than a cold-start Anvil. The
  // default 10s timeout from @viem/anvil isn't enough for slow public RPCs.
  startTimeout: 60_000,
  ...(FORK_RPC_URL && { forkUrl: FORK_RPC_URL }),
});

let publicClient: PublicClient;
let walletClient: WalletClient;
let testClient: TestClient;
let factoryAddress: Address;
let walletImplAddress: Address;
let paymasterAddress: Address;

const MAX_FEE = parseEther("1");

function buildInitPayload(signer: QuipSigner, vaultId: Hex) {
  const disaster = signer.generateKeyPair(vaultId).publicKey;
  const ownership = signer.generateKeyPair(vaultId).publicKey;
  const transactionKeys = Array.from({ length: MAX_KEYS }, () =>
    signer.generateKeyPair(vaultId).publicKey
  );
  const recoveryKeys = Array.from({ length: MAX_KEYS }, () =>
    signer.generateKeyPair(vaultId).publicKey
  );
  const verificationKeys = Array.from({ length: MAX_KEYS }, () =>
    signer.generateKeyPair(vaultId).publicKey
  );
  return {
    payload: encodeInit(
      disaster,
      ownership,
      transactionKeys,
      recoveryKeys,
      verificationKeys
    ),
    transactionKeys,
  };
}

// Conditional setup: only spin up Anvil + deploy when FORK_RPC_URL is set.
beforeAll(async () => {
  if (!SHOULD_RUN) return;
  await anvil.start();
  const transport = http(`http://127.0.0.1:${anvil.port}`);
  publicClient = createPublicClient({ chain: mainnet, transport });
  walletClient = createWalletClient({ chain: mainnet, transport, account });
  testClient = createTestClient({ chain: mainnet, mode: "anvil", transport });

  // Sanity: the canonical v0.7 EntryPoint is already deployed on real
  // mainnet. The fork should expose it without any setCode work.
  const epCode = await publicClient.getCode({
    address: CANONICAL_ENTRYPOINT_V07,
  });
  if (!epCode || epCode === "0x") {
    throw new Error(
      `Canonical EntryPoint v0.7 has no code at ${CANONICAL_ENTRYPOINT_V07} on the forked chain. ` +
        `Is FORK_RPC_URL pointing at mainnet (or a chain where the canonical EntryPoint exists)?`
    );
  }

  const chainId = await publicClient.getChainId();
  if (chainId !== 1) {
    // Not a hard failure — the SDK should still work on other chains.
    // But we expected mainnet config here; flag it.
    console.warn(
      `WARN: smoke fork connected to chainId ${chainId}; expected 1 (mainnet).`
    );
  }

  // Deploy QuipFactory.
  const factoryHash = await walletClient.deployContract({
    abi: quipFactoryAbi,
    bytecode: factoryBytecode,
    args: [account.address, MAX_FEE],
    account,
    chain: mainnet,
  });
  const factoryReceipt = await publicClient.waitForTransactionReceipt({
    hash: factoryHash,
  });
  factoryAddress = factoryReceipt.contractAddress!;

  // Deploy WOTSPlus library.
  const wotsHash = await walletClient.deployContract({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: wotsPlusAbi as any,
    bytecode: wotsPlusBytecode,
    account,
    chain: mainnet,
  });
  const wotsReceipt = await publicClient.waitForTransactionReceipt({
    hash: wotsHash,
  });
  const wotsAddr = wotsReceipt.contractAddress!;

  // Wallet impl + vet.
  const walletBytecode = linkBytecode(
    walletUnlinkedBytecode,
    walletArtifact.bytecode.linkReferences,
    wotsAddr
  );
  const implHash = await walletClient.deployContract({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: wotsPlusImplementationDeployAbi as any,
    bytecode: walletBytecode,
    args: [factoryAddress],
    account,
    chain: mainnet,
  });
  const implReceipt = await publicClient.waitForTransactionReceipt({
    hash: implHash,
  });
  walletImplAddress = implReceipt.contractAddress!;
  const vetHash = await walletClient.writeContract({
    chain: mainnet,
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "vetImplementation",
    args: [walletImplAddress],
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: vetHash });

  // Paymaster impl + ERC-1967 proxy + initialize + 1 ETH deposit.
  const pmBytecode = linkBytecode(
    paymasterUnlinkedBytecode,
    paymasterArtifact.bytecode.linkReferences,
    wotsAddr
  );
  const pmImplHash = await walletClient.deployContract({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: quipPaymasterDeployAbi as any,
    bytecode: pmBytecode,
    account,
    chain: mainnet,
  });
  const pmImplReceipt = await publicClient.waitForTransactionReceipt({
    hash: pmImplHash,
  });
  paymasterAddress = await deployErc1967Proxy(
    walletClient,
    publicClient,
    account,
    pmImplReceipt.contractAddress!,
    mainnet
  );
  const initHash = await walletClient.writeContract({
    chain: mainnet,
    address: paymasterAddress,
    abi: quipPaymasterAbi,
    functionName: "initialize",
    args: [account.address],
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: initHash });
  const depHash = await walletClient.writeContract({
    chain: mainnet,
    address: paymasterAddress,
    abi: quipPaymasterAbi,
    functionName: "deposit",
    args: [],
    value: parseEther("1"),
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: depHash });
}, 180_000);

afterAll(async () => {
  if (!SHOULD_RUN) return;
  await anvil.stop().catch(() => {});
}, 10_000);

// `describe.skip` when FORK_RPC_URL isn't set so the suite is a no-op
// for default test runs.
const maybeDescribe = SHOULD_RUN ? describe : describe.skip;

maybeDescribe("Forked-mainnet smoke (FORK_RPC_URL set)", () => {
  test(
    "end-to-end lifecycle: create wallet → execute → add keys → sponsored UserOp",
    async () => {
      // ─── 1. Create wallet via the SDK ─────────────────────────────────
      const quantumSecret = new Uint8Array(32).fill(0xa1);
      const signer = new QuipSigner(quantumSecret, createInMemoryBurnSet().consume);
      const vaultId = toHex(new Uint8Array(32).fill(0xa1));
      const init = buildInitPayload(signer, vaultId);

      const createHash = await walletClient.writeContract({
        chain: mainnet,
        address: factoryAddress,
        abi: quipFactoryAbi,
        functionName: "deployLatestWalletProxy",
        args: [vaultId, account.address, init.payload],
        account,
      });
      const createReceipt = await publicClient.waitForTransactionReceipt({
        hash: createHash,
      });

      // Parser sanity on a real-chain receipt.
      const createdEvents = parseQuipCreated(createReceipt);
      expect(createdEvents).toHaveLength(1);
      expect(createdEvents[0].creator.toLowerCase()).toBe(
        account.address.toLowerCase()
      );
      const walletAddress = createdEvents[0].quip;

      const client = new WOTSPlusImplementationClient(
        signer,
        vaultId,
        walletAddress,
        publicClient,
        walletClient,
        account.address,
        await publicClient.getChainId()
      );

      // ─── 2. ETH transfer via executeWithPayload ────────────────────
      // The wallet's `execute(bytes)` is `payable`; the caller forwards
      // the transferred value as `msg.value`. So the wallet's own balance
      // doesn't decrease — we check the recipient received the funds instead.
      const recipient = "0x000000000000000000000000000000000000DeaD" as const;
      const recipientBefore = await publicClient.getBalance({
        address: recipient,
      });
      const execReceipt = await client.executeWithPayload(
        recipient,
        parseEther("0.1"),
        "0x"
      );
      const execResult = parseWalletReceipt(execReceipt);
      if (execResult === null) throw new Error("expected non-null exec result");
      if (execResult.kind !== "executed")
        throw new Error(`expected executed, got ${execResult.kind}`);
      expect(execResult.target.toLowerCase()).toBe(recipient.toLowerCase());
      expect(execResult.value).toBe(parseEther("0.1"));
      // Successful execute → ExecutionSucceeded + KeyRotated both fire.
      expect(parseExecutionSucceeded(execReceipt)).toHaveLength(1);
      expect(parseKeyRotated(execReceipt)).toHaveLength(1);
      const recipientAfter = await publicClient.getBalance({
        address: recipient,
      });
      expect(recipientAfter - recipientBefore).toBe(parseEther("0.1"));

      // ─── 3. Reset verification keys (key management surface) ──────────
      const resetReceipt = await client.resetVerificationKeys();
      const resetEvents = parseKeysetReset(resetReceipt);
      expect(resetEvents).toHaveLength(1);
      expect(resetEvents[0].kind).toBe(KeyType.Verification);
      expect(resetEvents[0].signingKind).toBe(KeyType.Transaction);

      // ─── 4. Sponsored UserOp end-to-end via the EntryPoint ────────────
      // Register a verifier for this wallet on the paymaster.
      const pmClient = new QuipPaymasterClient({
        paymasterAddress,
        publicClient,
        walletClient,
        account: account.address,
        chainId: await publicClient.getChainId(),
      });
      const operatorSecret = new Uint8Array(32).fill(0xb2);
      const operator = new QuipSigner(operatorSecret, createInMemoryBurnSet().consume);
      const operatorVault = toHex(new Uint8Array(32).fill(0xb2));
      const currentVerifier = operator
        .generateKeyPair(operatorVault)
        .publicKey;
      await pmClient.setPqVerifier(walletAddress, currentVerifier);

      // Pre-deposit some ETH for the wallet at the EntryPoint so it doesn't
      // depend on the paymaster's pre-fund covering everything.
      const epDepositHash = await walletClient.writeContract({
        chain: mainnet,
        address: CANONICAL_ENTRYPOINT_V07,
        abi: entryPointV07Abi,
        functionName: "depositTo",
        args: [walletAddress],
        value: parseEther("0.5"),
        account,
      });
      await publicClient.waitForTransactionReceipt({ hash: epDepositHash });

      // Build wallet UserOp (prepare-only — paymaster fills in next).
      const prepared = await client.prepareExecuteUserOp(
        zeroAddress,
        0n,
        "0x"
      );

      // Paymaster signs over constituent fields and fills paymasterAndData.
      const sponsored = await pmClient.sponsorUserOp({
        userOp: prepared.userOp,
        operatorSigner: operator,
        vaultId: operatorVault,
        currentVerifier,
      });

      // Wallet signs LAST, committing to the final userOpHash (which now
      // includes paymasterAndData). This is the prepare → sponsor → sign
      // ordering documented in `walletClient.signExecuteUserOp`.
      const final = await client.signExecuteUserOp({
        ...prepared,
        userOp: sponsored.userOp,
      });

      // ─── Gas-sponsorship accounting: snapshot pre-stakes before handleOps ─
      // Both the paymaster and the wallet have *pre-staked ETH* at the
      // EntryPoint (`EntryPoint.balanceOf(addr)` — the wallet via
      // `depositTo(walletAddress)` above, the paymaster via setup
      // `pmClient.deposit(1 ETH)`). When `handleOps` runs a UserOp, the
      // EntryPoint debits gas from one of these pre-stakes:
      //   - paymasterAndData present → paymaster's pre-stake pays.
      //   - paymasterAndData empty   → wallet's own pre-stake pays.
      // The `UserOpSponsored` event firing alone doesn't prove WHICH
      // pre-stake was debited — it just proves `postOp` ran. The actual
      // "gas sponsorship works" claim is: with sponsorship, the paymaster's
      // pre-stake drops and the wallet's is untouched.
      const paymasterPreStakeBefore = await pmClient.getDeposit();
      const walletPreStakeBefore = (await client.getWalletState()).deposit;

      // Submit via the canonical EntryPoint's `handleOps`.
      const beneficiary = account.address;
      const handleOpsHash = await walletClient.writeContract({
        chain: mainnet,
        address: CANONICAL_ENTRYPOINT_V07,
        abi: entryPointV07Abi,
        functionName: "handleOps",
        args: [[final.userOp], beneficiary],
        account,
      });
      const handleOpsReceipt = await publicClient.waitForTransactionReceipt({
        hash: handleOpsHash,
      });
      expect(handleOpsReceipt.status).toBe("success");

      // UserOpSponsored fires from the paymaster's postOp.
      const sponsoredEvents = parseUserOpSponsored(handleOpsReceipt);
      expect(sponsoredEvents).toHaveLength(1);
      expect(sponsoredEvents[0].wallet.toLowerCase()).toBe(
        walletAddress.toLowerCase()
      );
      // mode 0 = opSucceeded.
      expect(sponsoredEvents[0].mode).toBe(0);
      // Event tells us the actual gas cost the EntryPoint charged. This is
      // what should have been deducted from the paymaster's deposit.
      const sponsoredCost = sponsoredEvents[0].actualGasCost;
      expect(sponsoredCost).toBeGreaterThan(0n);

      // ─── Gas-sponsorship accounting: prove the paymaster's pre-stake paid ─
      const paymasterPreStakeAfter = await pmClient.getDeposit();
      const walletPreStakeAfter = (await client.getWalletState()).deposit;

      const paymasterPreStakeDrop = paymasterPreStakeBefore - paymasterPreStakeAfter;
      const walletPreStakeDrop = walletPreStakeBefore - walletPreStakeAfter;

      // Paymaster's pre-stake MUST have dropped — that's the whole claim
      // of "gas sponsorship". Invariant: `paymasterDrop >= sponsoredCost`.
      //   - `sponsoredCost` is what the EntryPoint passed to `postOp` as
      //     `actualGasCost` — the cost up to that point.
      //   - The full debit also includes postOp gas, since the EntryPoint
      //     debits the paymaster's pre-stake after postOp returns. So the
      //     drop is slightly larger than the event value (typically <5%).
      //   - We sanity-cap the upper bound at 2x `sponsoredCost` to catch
      //     accounting bugs (e.g. double-debit) — real overhead is far less.
      expect(paymasterPreStakeDrop).toBeGreaterThanOrEqual(sponsoredCost);
      expect(paymasterPreStakeDrop).toBeLessThan(sponsoredCost * 2n);

      // Wallet's pre-stake MUST be untouched. If sponsorship routed
      // correctly, the EntryPoint never debited the wallet's pre-stake —
      // it pulled the full cost from the paymaster's pre-stake instead.
      expect(walletPreStakeDrop).toBe(0n);
      expect(walletPreStakeAfter).toBe(walletPreStakeBefore);

      // ─── 5. Unsponsored UserOp control — proves the pre-stake routing ──
      // Submit an identical UserOp shape WITHOUT a paymaster section. The
      // EntryPoint should now debit the WALLET's own pre-stake instead.
      // This is the direct contrast that makes step 4's claim concrete:
      // with `paymasterAndData` present, the paymaster's pre-stake pays;
      // with `paymasterAndData = "0x"`, the wallet's pre-stake pays.
      //
      // Note: this is NOT the wallet "sponsoring itself". The wallet
      // earlier pre-staked 0.5 ETH at the EntryPoint via `depositTo` —
      // the EntryPoint is now drawing gas from that prepaid pool, the
      // same way it would draw from a paymaster's pre-stake in the
      // sponsored case. ERC-4337 just has these two payment paths.
      const walletPreStakeBeforeControl = walletPreStakeAfter;
      const paymasterPreStakeBeforeControl = paymasterPreStakeAfter;

      // buildExecuteUserOp = prepareExecuteUserOp + signExecuteUserOp, no
      // paymaster section. The wallet signs directly.
      const unsponsored = await client.buildExecuteUserOp(
        zeroAddress,
        0n,
        "0x"
      );
      const unsponsoredHash = await walletClient.writeContract({
        chain: mainnet,
        address: CANONICAL_ENTRYPOINT_V07,
        abi: entryPointV07Abi,
        functionName: "handleOps",
        args: [[unsponsored.userOp], beneficiary],
        account,
      });
      const unsponsoredReceipt = await publicClient.waitForTransactionReceipt({
        hash: unsponsoredHash,
      });
      expect(unsponsoredReceipt.status).toBe("success");

      const walletPreStakeAfterControl = (await client.getWalletState()).deposit;
      const paymasterPreStakeAfterControl = await pmClient.getDeposit();

      const walletControlDrop =
        walletPreStakeBeforeControl - walletPreStakeAfterControl;
      const paymasterControlDrop =
        paymasterPreStakeBeforeControl - paymasterPreStakeAfterControl;

      // Mirror of step 4: wallet's pre-stake drops, paymaster's untouched.
      expect(walletControlDrop).toBeGreaterThan(0n);
      expect(paymasterControlDrop).toBe(0n);
      // No UserOpSponsored event for this op — the paymaster wasn't involved.
      expect(parseUserOpSponsored(unsponsoredReceipt)).toHaveLength(0);

      // ─── 6. Read aggregator on a non-trivial wallet ────────────────────
      const state = await client.getWalletState();
      expect(state.owner.toLowerCase()).toBe(account.address.toLowerCase());
      expect(state.transactionKeys.length).toBeGreaterThan(0);
      // We added 1 verification key in step 3.
      expect(state.keyCounts.verification).toBeGreaterThanOrEqual(1n);
    },
    300_000
  );
});

// Print a clear note when the suite is skipped, so it's obvious from CI
// logs that the smoke didn't run vs ran-and-passed.
if (!SHOULD_RUN) {
  // eslint-disable-next-line no-console
  console.log(
    "[smoke.fork] FORK_RPC_URL not set; forked-mainnet smoke skipped. " +
      "To run: FORK_RPC_URL=https://eth.merkle.io npm run test:unit -- --testPathPattern smoke.fork"
  );
}
