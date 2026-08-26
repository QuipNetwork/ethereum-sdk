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
// Live-anvil end-to-end SMOKE test for the Shrincs TS SDK: proves an FE
// consumer can deploy and operate a ShrincsWallet + ShrincsPaymaster against
// real on-chain contracts. Each sub-flow runs as its own `it` with an isolated
// wallet (distinct seedByte) so tests never depend on each other.
import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
} from "@jest/globals";
import {
  type Address,
  type Hex,
  BaseError,
  ContractFunctionRevertedError,
  getAddress,
  parseEther,
  parseEventLogs,
  toFunctionSelector,
  toHex,
} from "viem";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

import { entryPointV07Abi } from "../../abi/EntryPointV07.js";
import { walletFactoryAbi } from "../../abi/WalletFactory.js";
import { CANONICAL_ENTRYPOINT_V07 } from "../../addresses.js";
import { shrincsWalletAbi } from "../abi/ShrincsWallet.js";
import { shrincsPaymasterAbi } from "../abi/ShrincsPaymaster.js";
import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import {
  AuthLeafInTargetsError,
  EmptyLeavesError,
  Erc1271ValidationResult,
  ExecuteFeeExceedsCapError,
  LeafOutOfRangeError,
  StaleStatefulLeafError,
  VerifierMismatchError,
} from "../errors.js";
import { v1Commitment } from "../addresses.js";
import { encodeInitPayload, publicKeyCommitment } from "../shrincsCodec.js";
import { ShrincsPaymasterClient } from "../shrincsPaymasterClient.js";
import {
  DEFAULT_ACCOUNT,
  SHRINCS_ANVIL_PORTS,
  type ShrincsAnvilStack,
  createFreshShrincsWallet,
  deployFreshPaymasterProxy,
  initializePaymaster,
  makeShrincsFactoryClient,
  makeShrincsSigner,
  setupShrincsAnvilStack,
  stopShrincsAnvilStack,
} from "./utils/shrincsAnvilFixture.js";

// Anvil prefunded dev account #0 — the wallet owner used by the fixture
// (the factory deploy `to` arg == stack.account.address).
const OWNER_PRIV =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const ownerAccount = privateKeyToAccount(OWNER_PRIV);

const RECIPIENT = "0x000000000000000000000000000000000000d00d" as Address;
const SIGNING_BUDGET = 4;
const MAX_SIGS = SIGNING_BUDGET;
// The first four signing leaves, named by their position in the signing budget.
const LEAF_1 = 1;
const LEAF_2 = 2;
const LEAF_3 = 3;
const LEAF_4 = 4;

let stack: ShrincsAnvilStack;

beforeAll(async () => {
  stack = await setupShrincsAnvilStack({ port: SHRINCS_ANVIL_PORTS.smoke });
}, 120_000);

afterAll(async () => {
  await stopShrincsAnvilStack(stack);
}, 10_000);

describe("Shrincs SDK live-anvil smoke", () => {
  // ── (a) deploy + reads ───────────────────────────────────────────────
  it("a. deploys a wallet, reads expected state, and resolves the same address", async () => {
    const seedByte = 0x10;
    const { client, signer, derivationIndex, erc1271DerivationIndex, walletAddress } =
      await createFreshShrincsWallet(stack, seedByte, {
        maxSignatures: MAX_SIGS,
      });

    const state = await client.getWalletState();
    expect(getAddress(state.owner)).toBe(getAddress(stack.account.address));
    expect(state.maxSignatures).toBe(MAX_SIGS);
    expect(state.statefulLeavesUsed).toBe(0);
    expect(state.remainingStatefulSignatures).toBe(SIGNING_BUDGET);

    // Commitment installed on-chain reproduces from the signer.
    const mainKey = signer.recoverKeyPair(derivationIndex, {
      maxSignatures: MAX_SIGS,
    });
    expect(state.shrincsPublicKeyCommitment.toLowerCase()).toBe(
      mainKey.publicKeyCommitment.toLowerCase()
    );

    // The wallet delegates signature crypto to the fixture's external verifier
    // (pinned as an implementation immutable).
    expect(getAddress(await client.getShrincsVerifier())).toBe(
      getAddress(stack.shrincsVerifier)
    );

    // getShrincsWallet resolves the same address and validates the commitment.
    const factory = makeShrincsFactoryClient(stack);
    const resolved = await factory.getShrincsWallet({
      derivationIndex,
      erc1271: { derivationIndex: erc1271DerivationIndex, maxSignatures: MAX_SIGS },
      owner: stack.account.address,
      signer,
      maxSignatures: MAX_SIGS,
    });
    expect(getAddress(resolved.walletAddress)).toBe(getAddress(walletAddress));
  }, 120_000);

  // ── (b) stateful execute ─────────────────────────────────────────────
  it("b. executes a value transfer with a real SHRINCS signature, incrementing statefulLeavesUsed", async () => {
    const { client } = await createFreshShrincsWallet(stack, 0x20, {
      maxSignatures: MAX_SIGS,
    });

    const before = await stack.publicClient.getBalance({ address: RECIPIENT });
    const value = parseEther("0.25");

    const stateBefore = await client.getWalletState();
    expect(stateBefore.statefulLeavesUsed).toBe(0);
    expect(stateBefore.actionNonce).toBe(0n);

    await client.execute({ target: RECIPIENT, value });

    const after = await stack.publicClient.getBalance({ address: RECIPIENT });
    expect(after - before).toBe(value);

    const stateAfter = await client.getWalletState();
    expect(stateAfter.statefulLeavesUsed).toBe(1);
    expect(await client.isStatefulLeafUsed(LEAF_1)).toBe(true);
    expect(stateAfter.actionNonce).toBe(1n);
  }, 120_000);

  // ── (c) lowest-unused-leaf / no in-memory burn ───────────────────────
  it("c. two sequential executes consume leaf 1 then leaf 2 (re-reads on-chain bitmap)", async () => {
    const { client } = await createFreshShrincsWallet(stack, 0x30, {
      maxSignatures: MAX_SIGS,
    });

    const r1 = await client.execute({ target: RECIPIENT, value: parseEther("0.1") });
    const leaves1 = parseEventLogs({
      abi: shrincsWalletAbi,
      logs: r1.logs,
      eventName: "StatefulSignatureVerified",
    });
    expect(leaves1.length).toBe(1);
    expect(Number(leaves1[0].args.leaf)).toBe(LEAF_1);

    const r2 = await client.execute({ target: RECIPIENT, value: parseEther("0.1") });
    const leaves2 = parseEventLogs({
      abi: shrincsWalletAbi,
      logs: r2.logs,
      eventName: "StatefulSignatureVerified",
    });
    expect(leaves2.length).toBe(1);
    expect(Number(leaves2[0].args.leaf)).toBe(LEAF_2);

    const state = await client.getWalletState();
    expect(state.statefulLeavesUsed).toBe(2);
    // Each landed execute consumed one signature => actionNonce went 0 -> 1 -> 2
    // (the client re-read the live nonce before signing the second op).
    expect(state.actionNonce).toBe(2n);
  }, 120_000);

  // ── (d) stale-leaf replay rejection ──────────────────────────────────
  it("d. replaying the same leaf reverts with StaleStatefulLeaf", async () => {
    const { client } = await createFreshShrincsWallet(stack, 0x40, {
      maxSignatures: MAX_SIGS,
    });

    // Force the first signing leaf, succeed.
    await client.execute(
      { target: RECIPIENT, value: parseEther("0.05") },
      { leaf: LEAF_1 }
    );
    expect(await client.isStatefulLeafUsed(LEAF_1)).toBe(true);

    // Reuse the leaf — must revert. The decoded error should be StaleStatefulLeaf.
    let caught: unknown = null;
    try {
      await client.execute(
        { target: RECIPIENT, value: parseEther("0.05") },
        { leaf: LEAF_1 }
      );
    } catch (e) {
      caught = e;
    }
    expect(caught).not.toBeNull();
    // The SDK decodes the on-chain `StaleStatefulLeaf` revert into a typed error.
    expect(caught).toBeInstanceOf(StaleStatefulLeafError);
    expect((caught as StaleStatefulLeafError).code).toBe(
      "SHRINCS_STALE_STATEFUL_LEAF"
    );
  }, 120_000);

  // ── (e) ERC-1271 round-trip ──────────────────────────────────────────
  it("e. signErc1271 produces a blob the wallet accepts (isValidSignature + debug Ok)", async () => {
    const { client, signer, erc1271DerivationIndex } =
      await createFreshShrincsWallet(stack, 0x50, { maxSignatures: MAX_SIGS });

    // The ERC-1271 verifier key was installed at creation under erc1271DerivationIndex.
    const state = await client.getWalletState();
    const erc1271KeyPair = signer.recoverKeyPair(erc1271DerivationIndex, {
      maxSignatures: MAX_SIGS,
    });
    expect(erc1271KeyPair.publicKeyCommitment.toLowerCase()).toBe(
      state.erc1271Commitment.toLowerCase()
    );

    const hash =
      "0x1111111111111111111111111111111111111111111111111111111111111111" as Hex;
    const blob = await client.signErc1271({
      hash,
      erc1271KeyPair,
      owner: ownerAccount,
    });

    expect(await client.isValidSignature(hash, blob)).toBe(true);
    expect(await client.debugIsValidSignature(hash, blob)).toBe(
      Erc1271ValidationResult.Ok
    );

    // Supersession: the blob binds the live action nonce, so ANY consumed
    // wallet signature (here an execute) invalidates it; re-signing against
    // the advanced nonce restores validity.
    await client.execute({ target: RECIPIENT, value: parseEther("0.01") });
    expect(await client.isValidSignature(hash, blob)).toBe(false);
    expect(await client.debugIsValidSignature(hash, blob)).toBe(
      Erc1271ValidationResult.InvalidShrincsSignature
    );

    const freshBlob = await client.signErc1271({
      hash,
      erc1271KeyPair,
      owner: ownerAccount,
    });
    expect(await client.isValidSignature(hash, freshBlob)).toBe(true);
  }, 120_000);

  // ── (f) sponsored userOp (ERC-4337) ──────────────────────────────────
  it("f. sponsors a wallet execute userOp via the paymaster and submits handleOps", async () => {
    // Wallet whose userOp will be sponsored. No EntryPoint deposit needed: the
    // paymaster covers prefund.
    const { client: walletClient } = await createFreshShrincsWallet(stack, 0x60, {
      maxSignatures: MAX_SIGS,
    });

    // Operator signer holds the paymaster's sponsorship verifier key.
    const operatorSeed = 0x61;
    const operator = await makeShrincsSigner(operatorSeed);
    const operatorIndex = operatorSeed;
    const operatorCommitment = toHex(new Uint8Array(32).fill(operatorSeed));
    const verifierKey = operator.recoverKeyPair(operatorIndex, {
      maxSignatures: MAX_SIGS,
    });

    // Initialize the paymaster with the operator's full verifier bundle (the
    // contract derives the commitment + leaf budget from it), then fund its
    // EntryPoint deposit + stake so it can sponsor.
    await initializePaymaster(stack, {
      owner: stack.account.address,
      publicKey: verifierKey.publicKey,
      hashSuite: HASH_SUITE_KECCAK_256,
    });

    const pmClient = new ShrincsPaymasterClient({
      paymasterAddress: stack.paymasterProxy,
      publicClient: stack.publicClient,
      walletClient: stack.walletClient,
      signer: operator,
      commitment: operatorCommitment,
      derivationIndex: operatorIndex,
      chainId: foundry.id,
      account: stack.account.address,
    });

    await pmClient.deposit(parseEther("2"));
    await pmClient.addStake({ unstakeDelaySec: 86_400, value: parseEther("1") });

    // Sanity: verifier commitment installed.
    const verifier = await pmClient.getShrincsVerifier();
    expect(verifier.commitment.toLowerCase()).toBe(
      verifierKey.publicKeyCommitment.toLowerCase()
    );

    // Build the unsigned execute userOp.
    const recipientBefore = await stack.publicClient.getBalance({
      address: RECIPIENT,
    });
    const value = parseEther("0.3");
    // Wallet must hold the transfer value (paymaster only covers gas).
    await stack.testClient.setBalance({
      address: walletClient.walletAddress,
      value: parseEther("5"),
    });

    const block = await stack.publicClient.getBlock();
    const baseFee = block.baseFeePerGas ?? parseEther("0.000000001");
    const maxPriorityFeePerGas = parseEther("0.000000001");
    const maxFeePerGas = baseFee * 2n + maxPriorityFeePerGas;
    const nonce = (await stack.publicClient.readContract({
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "getNonce",
      args: [walletClient.walletAddress, 0n],
    })) as bigint;

    // `maxFee` here is the wallet's signed EXECUTION-fee ceiling (rides in the
    // execute callData) — unrelated to the gas-price `maxFeePerGas` below, and
    // also distinct from the fixture's factory-level MAX_FEE constructor cap.
    const walletState = await walletClient.getWalletState();
    let userOp = walletClient.buildExecuteUserOp({
      target: RECIPIENT,
      value,
      data: "0x",
      maxFee: walletState.executeFee,
      nonce,
      maxFeePerGas,
      maxPriorityFeePerGas,
    });

    // Paymaster signs FIRST (fills paymasterAndData), then the wallet signs over
    // the final userOpHash that includes paymasterAndData.
    const { paymasterAndData } = await pmClient.sponsorUserOp({ userOp });
    userOp = { ...userOp, paymasterAndData };

    const signed = await walletClient.signExecuteUserOp({
      userOp,
      entryPoint: CANONICAL_ENTRYPOINT_V07,
      owner: ownerAccount,
    });

    const handleHash = await stack.walletClient.writeContract({
      chain: foundry,
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "handleOps",
      args: [[signed.userOp], stack.account.address],
      account: stack.account,
      gas: 6_000_000n,
    });
    const receipt = await stack.publicClient.waitForTransactionReceipt({
      hash: handleHash,
    });

    // EntryPoint reports success.
    const opEvents = parseEventLogs({
      abi: entryPointV07Abi,
      logs: receipt.logs,
      eventName: "UserOperationEvent",
    });
    expect(opEvents.length).toBe(1);
    expect(opEvents[0].args.success).toBe(true);
    expect((opEvents[0].args.paymaster as Address).toLowerCase()).toBe(
      stack.paymasterProxy.toLowerCase()
    );

    // Paymaster emitted SponsorshipVerified + UserOpSponsored.
    const sponsorshipEvents = parseEventLogs({
      abi: shrincsPaymasterAbi,
      logs: receipt.logs,
      eventName: "SponsorshipVerified",
    });
    expect(sponsorshipEvents.length).toBe(1);
    expect(getAddress(sponsorshipEvents[0].args.wallet as Address)).toBe(
      getAddress(walletClient.walletAddress)
    );

    const sponsoredEvents = parseEventLogs({
      abi: shrincsPaymasterAbi,
      logs: receipt.logs,
      eventName: "UserOpSponsored",
    });
    expect(sponsoredEvents.length).toBe(1);

    // Call effect: recipient received the value.
    const recipientAfter = await stack.publicClient.getBalance({
      address: RECIPIENT,
    });
    expect(recipientAfter - recipientBefore).toBe(value);
  }, 180_000);

  // ── (g) execute-fee cap semantics ────────────────────────────────────
  it("g. enforces the signed maxFee ceiling and charges the live fee below it", async () => {
    const { client } = await createFreshShrincsWallet(stack, 0x70, {
      maxSignatures: MAX_SIGS,
    });

    // NOTE on naming: the fixture's DEFAULT_MAX_FEE is the FACTORY-level
    // constructor cap bounding what the owner may set `executeFee` to; the
    // per-call `maxFee` exercised here is the signer's own execution-fee
    // ceiling. Two different knobs.
    const setExecuteFee = async (fee: bigint) => {
      const hash = await stack.walletClient.writeContract({
        chain: foundry,
        address: stack.factoryAddress,
        abi: walletFactoryAbi,
        functionName: "setExecuteFee",
        args: [fee],
        account: stack.account,
      });
      await stack.publicClient.waitForTransactionReceipt({ hash });
    };

    try {
      await setExecuteFee(parseEther("0.002"));

      // Live fee above the signed ceiling: the op signs at LEAF_1, then the
      // pre-flight simulation reverts and the SDK decodes it into the typed cap
      // error. Nothing broadcasts, so the on-chain bitmap shows LEAF_1 unused.
      // The one-time key at LEAF_1 has already signed in-process, so the client
      // burns it (never reuse an exposed OTS leaf) and the retry below takes
      // LEAF_2.
      let caught: unknown = null;
      try {
        await client.execute({
          target: RECIPIENT,
          value: parseEther("0.01"),
          maxFee: parseEther("0.001"),
        });
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ExecuteFeeExceedsCapError);
      expect((caught as ExecuteFeeExceedsCapError).fee).toBe(parseEther("0.002"));
      expect((caught as ExecuteFeeExceedsCapError).maxFee).toBe(parseEther("0.001"));
      expect(await client.isStatefulLeafUsed(LEAF_1)).toBe(false);

      // Ceiling with headroom above the live fee: lands at LEAF_2 (LEAF_1 was
      // burned above), and the factory is credited the LIVE fee — not the
      // signed ceiling.
      const factoryBefore = await stack.publicClient.getBalance({
        address: stack.factoryAddress,
      });
      const recipientBefore = await stack.publicClient.getBalance({
        address: RECIPIENT,
      });
      await client.execute({
        target: RECIPIENT,
        value: parseEther("0.01"),
        maxFee: parseEther("0.005"),
      });
      const factoryAfter = await stack.publicClient.getBalance({
        address: stack.factoryAddress,
      });
      const recipientAfter = await stack.publicClient.getBalance({
        address: RECIPIENT,
      });
      expect(factoryAfter - factoryBefore).toBe(parseEther("0.002"));
      expect(recipientAfter - recipientBefore).toBe(parseEther("0.01"));
      expect(await client.isStatefulLeafUsed(LEAF_1)).toBe(false);
      expect(await client.isStatefulLeafUsed(LEAF_2)).toBe(true);
    } finally {
      // The factory fee is global to the shared anvil stack — restore it.
      await setExecuteFee(0n);
    }
  }, 120_000);

  // ── (h) surgical leaf revocation ─────────────────────────────────────
  it("h. markLeavesUsed burns targets without advancing the nonce, auth leaf picked outside the set", async () => {
    const { client } = await createFreshShrincsWallet(stack, 0x80, {
      maxSignatures: MAX_SIGS,
    });

    // Client-side guards fire BEFORE signing — no tx, no leaf burned.
    await expect(client.markLeavesUsed({ leaves: [] })).rejects.toBeInstanceOf(
      EmptyLeavesError
    );
    await expect(
      client.markLeavesUsed({ leaves: [LEAF_2, LEAF_3] }, { leaf: LEAF_2 })
    ).rejects.toBeInstanceOf(AuthLeafInTargetsError);
    await expect(
      client.markLeavesUsed({ leaves: [0] })
    ).rejects.toBeInstanceOf(LeafOutOfRangeError);
    await expect(
      client.markLeavesUsed({ leaves: [MAX_SIGS + 1] })
    ).rejects.toBeInstanceOf(LeafOutOfRangeError);
    expect((await client.getWalletState()).statefulLeavesUsed).toBe(0);

    // Burn [LEAF_1, LEAF_3]. LEAF_1 is the lowest FREE signing leaf, so this
    // proves the auto-pick excludes the target set: the authorizing leaf must
    // be LEAF_2.
    const receipt = await client.markLeavesUsed({ leaves: [LEAF_1, LEAF_3] });

    const revoked = parseEventLogs({
      abi: shrincsWalletAbi,
      logs: receipt.logs,
      eventName: "LeafRevoked",
    });
    expect(revoked.map((l) => Number(l.args.leaf)).sort((a, b) => a - b)).toEqual([
      LEAF_1,
      LEAF_3,
    ]);
    const verified = parseEventLogs({
      abi: shrincsWalletAbi,
      logs: receipt.logs,
      eventName: "StatefulSignatureVerified",
    });
    expect(verified.length).toBe(1);
    expect(Number(verified[0].args.leaf)).toBe(LEAF_2);

    const state = await client.getWalletState();
    expect(await client.isStatefulLeafUsed(LEAF_1)).toBe(true);
    expect(await client.isStatefulLeafUsed(LEAF_2)).toBe(true); // authorizing leaf
    expect(await client.isStatefulLeafUsed(LEAF_3)).toBe(true);
    expect(state.statefulLeavesUsed).toBe(3);
    // SURGICAL: unlike every other landed action, revocation must NOT advance
    // the action nonce.
    expect(state.actionNonce).toBe(0n);

    // A revoked leaf can no longer sign: forcing it is rejected at pre-flight
    // with the decoded stale-leaf error.
    let caught: unknown = null;
    try {
      await client.execute(
        { target: RECIPIENT, value: parseEther("0.01") },
        { leaf: LEAF_3 }
      );
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(StaleStatefulLeafError);

    // The untouched LEAF_4 still works normally afterward: it is the lowest free
    // signing leaf, so the auto-pick lands there.
    await client.execute({ target: RECIPIENT, value: parseEther("0.01") });
    const final = await client.getWalletState();
    expect(await client.isStatefulLeafUsed(LEAF_4)).toBe(true);
    expect(final.statefulLeavesUsed).toBe(4);
    expect(final.actionNonce).toBe(1n); // only the execute advanced it
  }, 120_000);

  // ── (i) surgical property end-to-end (pre-signed userOp survives) ────
  it("i. a userOp signed BEFORE a revocation of a different leaf still lands after it", async () => {
    const { client } = await createFreshShrincsWallet(stack, 0x90, {
      maxSignatures: MAX_SIGS,
    });

    // Self-funded 4337: the wallet's EntryPoint deposit pays prefund (no
    // paymaster needed), and the wallet holds the transfer value.
    await client.addDeposit(parseEther("1"));
    await stack.testClient.setBalance({
      address: client.walletAddress,
      value: parseEther("5"),
    });

    const block = await stack.publicClient.getBlock();
    const baseFee = block.baseFeePerGas ?? parseEther("0.000000001");
    const maxPriorityFeePerGas = parseEther("0.000000001");
    const maxFeePerGas = baseFee * 2n + maxPriorityFeePerGas;
    const nonce = (await stack.publicClient.readContract({
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "getNonce",
      args: [client.walletAddress, 0n],
    })) as bigint;

    const value = parseEther("0.2");
    const walletState = await client.getWalletState();
    const userOp = client.buildExecuteUserOp({
      target: RECIPIENT,
      value,
      data: "0x",
      maxFee: walletState.executeFee,
      nonce,
      maxFeePerGas,
      maxPriorityFeePerGas,
    });
    // Signed at LEAF_1 (lowest unused signing leaf), binding actionNonce 0 —
    // now OUTSTANDING.
    const signed = await client.signExecuteUserOp({
      userOp,
      entryPoint: CANONICAL_ENTRYPOINT_V07,
      owner: ownerAccount,
    });
    expect(signed.leaf).toBe(LEAF_1);

    // Revoke LEAF_3 while the op is in flight. The auth leaf must be forced
    // OFF LEAF_1: the bitmap still shows LEAF_1 free (the op hasn't landed),
    // and the client cannot know it signed off-chain — this is the documented
    // client-side leaf discipline.
    await client.markLeavesUsed({ leaves: [LEAF_3] }, { leaf: LEAF_2 });
    expect((await client.getWalletState()).actionNonce).toBe(0n);

    // The pre-signed op still lands: revocation superseded nothing.
    const recipientBefore = await stack.publicClient.getBalance({
      address: RECIPIENT,
    });
    const handleHash = await stack.walletClient.writeContract({
      chain: foundry,
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "handleOps",
      args: [[signed.userOp], stack.account.address],
      account: stack.account,
      gas: 6_000_000n,
    });
    const receipt = await stack.publicClient.waitForTransactionReceipt({
      hash: handleHash,
    });
    const opEvents = parseEventLogs({
      abi: entryPointV07Abi,
      logs: receipt.logs,
      eventName: "UserOperationEvent",
    });
    expect(opEvents.length).toBe(1);
    expect(opEvents[0].args.success).toBe(true);

    const recipientAfter = await stack.publicClient.getBalance({
      address: RECIPIENT,
    });
    expect(recipientAfter - recipientBefore).toBe(value);

    const final = await client.getWalletState();
    expect(await client.isStatefulLeafUsed(LEAF_1)).toBe(true); // the landed op
    expect(await client.isStatefulLeafUsed(LEAF_2)).toBe(true); // revocation auth
    expect(await client.isStatefulLeafUsed(LEAF_3)).toBe(true); // revoked target
    expect(final.actionNonce).toBe(1n); // only the landed op advanced it
  }, 180_000);

  // ── (j) paymaster fiat revocation + stateful-only key rotation ───────
  it("j. paymaster markLeavesUsed spends budget; rotateStatefulKey carries the stateless half into a fresh epoch that sponsors", async () => {
    // Own proxy: this test owns the verifier's whole epoch/bitmap lifecycle,
    // so it must not share the stack proxy that test (f) initialized.
    const paymaster = await deployFreshPaymasterProxy(stack);

    // ONE operator signer, two derivation indices: index1 = the initial key,
    // index2 = the rotation target (real operators rotate within one master
    // secret — that is what makes the post-rotation graft recoverable).
    const operator = await makeShrincsSigner(0xa0);
    const index1 = 0xa0;
    const index2 = 0xa1;
    const vault1 = toHex(new Uint8Array(32).fill(0xa0));
    const key1 = operator.recoverKeyPair(index1, { maxSignatures: MAX_SIGS });

    await initializePaymaster(stack, {
      owner: stack.account.address,
      publicKey: key1.publicKey,
      paymaster,
    });

    const pmClient = new ShrincsPaymasterClient({
      paymasterAddress: paymaster,
      publicClient: stack.publicClient,
      walletClient: stack.walletClient,
      signer: operator,
      commitment: vault1,
      derivationIndex: index1,
      chainId: foundry.id,
      account: stack.account.address,
    });

    // Client-side guard: an empty batch never reaches the chain. Contract
    // guards decode through gas estimation: out-of-range reverts the batch.
    await expect(pmClient.markLeavesUsed([])).rejects.toBeInstanceOf(
      EmptyLeavesError
    );
    await expect(pmClient.markLeavesUsed([0])).rejects.toBeInstanceOf(
      LeafOutOfRangeError
    );
    await expect(
      pmClient.markLeavesUsed([MAX_SIGS + 1])
    ).rejects.toBeInstanceOf(LeafOutOfRangeError);

    // Fiat revocation (no signature, owner tx) spends budget exactly like a
    // landed sponsorship: every fresh mark decrements what's left.
    const revocation = await pmClient.markLeavesUsed([1, 3]);
    const revoked = parseEventLogs({
      abi: shrincsPaymasterAbi,
      logs: revocation.logs,
      eventName: "LeafRevoked",
    });
    expect(revoked.map((l) => Number(l.args.leaf)).sort()).toEqual([1, 3]);
    expect(await pmClient.isStatefulLeafUsed(1)).toBe(true);
    expect(await pmClient.isStatefulLeafUsed(3)).toBe(true);
    let verifier = await pmClient.getShrincsVerifier();
    expect(verifier.statefulLeavesUsed).toBe(2);

    // Idempotent skip: a used target emits the skip event and never
    // double-counts; the fresh target in the same batch still lands.
    const rerun = await pmClient.markLeavesUsed([3, 4]);
    const skipped = parseEventLogs({
      abi: shrincsPaymasterAbi,
      logs: rerun.logs,
      eventName: "LeafRevocationSkipped",
    });
    expect(skipped.map((l) => Number(l.args.leaf))).toEqual([3]);
    verifier = await pmClient.getShrincsVerifier();
    expect(verifier.statefulLeavesUsed).toBe(3);

    // Rotate to vault2's fresh stateful subkey with a BIGGER budget (the
    // budget rides inside the 68-byte encoding — each rotation may change it).
    const NEW_MAX = 8;
    const key2 = operator.recoverKeyPair(index2, { maxSignatures: NEW_MAX });
    const rotation = await pmClient.rotateStatefulKey({
      nextStatefulPublicKey: key2.publicKey.statefulPublicKey,
    });
    const rotatedEvents = parseEventLogs({
      abi: shrincsPaymasterAbi,
      logs: rotation.logs,
      eventName: "KeyRotated",
    });
    expect(rotatedEvents.length).toBe(1);
    expect(Number(rotatedEvents[0].args.maxSignatures)).toBe(NEW_MAX);

    // The installed commitment is the CARRIED-FORWARD bundle (key2's stateful
    // subkey + key1's stateless half) — NOT key2's own full-bundle commitment.
    verifier = await pmClient.getShrincsVerifier();
    const expectedCommitment = publicKeyCommitment({
      statefulPublicKey: key2.publicKey.statefulPublicKey,
      pkSeed: key1.publicKey.pkSeed,
      hypertreeRoot: key1.publicKey.hypertreeRoot,
    });
    expect(verifier.commitment.toLowerCase()).toBe(
      expectedCommitment.toLowerCase()
    );
    expect(verifier.commitment.toLowerCase()).not.toBe(
      key2.publicKeyCommitment.toLowerCase()
    );
    expect(verifier.keyVersion).toBe(1n);
    expect(verifier.maxSignatures).toBe(NEW_MAX);
    expect(verifier.statefulLeavesUsed).toBe(0);
    expect(await pmClient.isStatefulLeafUsed(1)).toBe(false); // fresh namespace

    // The stale vault1 client is locked out BEFORE any tx is submitted.
    await expect(
      pmClient.rotateStatefulKey({
        nextStatefulPublicKey: key2.publicKey.statefulPublicKey,
      })
    ).rejects.toBeInstanceOf(VerifierMismatchError);

    // Post-rotation operator keypair: graft vault2's stateful secrets onto
    // vault1's stateless half — reproduces the installed commitment exactly.
    const grafted = operator.deriveKeyPair({
      statefulIndex: index2,
      statelessIndex: index1,
      maxSignatures: NEW_MAX,
    });
    expect(grafted.publicKeyCommitment.toLowerCase()).toBe(
      verifier.commitment.toLowerCase()
    );
    const pmClient2 = new ShrincsPaymasterClient({
      paymasterAddress: paymaster,
      publicClient: stack.publicClient,
      walletClient: stack.walletClient,
      signer: operator,
      commitment: vault1,
      derivationIndex: index2,
      chainId: foundry.id,
      account: stack.account.address,
      keypair: grafted,
    });

    // Full sponsorship under the ROTATED key: fund, sponsor, land a real op.
    await pmClient2.deposit(parseEther("2"));
    await pmClient2.addStake({ unstakeDelaySec: 86_400, value: parseEther("1") });

    const { client: walletClient } = await createFreshShrincsWallet(stack, 0xa2, {
      maxSignatures: MAX_SIGS,
    });
    await stack.testClient.setBalance({
      address: walletClient.walletAddress,
      value: parseEther("5"),
    });

    const block = await stack.publicClient.getBlock();
    const baseFee = block.baseFeePerGas ?? parseEther("0.000000001");
    const maxPriorityFeePerGas = parseEther("0.000000001");
    const maxFeePerGas = baseFee * 2n + maxPriorityFeePerGas;
    const nonce = (await stack.publicClient.readContract({
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "getNonce",
      args: [walletClient.walletAddress, 0n],
    })) as bigint;

    const value = parseEther("0.1");
    const recipientBefore = await stack.publicClient.getBalance({
      address: RECIPIENT,
    });
    const walletState = await walletClient.getWalletState();
    let userOp = walletClient.buildExecuteUserOp({
      target: RECIPIENT,
      value,
      data: "0x",
      maxFee: walletState.executeFee,
      nonce,
      maxFeePerGas,
      maxPriorityFeePerGas,
    });
    const { paymasterAndData, leaf } = await pmClient2.sponsorUserOp({ userOp });
    userOp = { ...userOp, paymasterAndData };
    const signed = await walletClient.signExecuteUserOp({
      userOp,
      entryPoint: CANONICAL_ENTRYPOINT_V07,
      owner: ownerAccount,
    });

    const handleHash = await stack.walletClient.writeContract({
      chain: foundry,
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "handleOps",
      args: [[signed.userOp], stack.account.address],
      account: stack.account,
      gas: 6_000_000n,
    });
    const receipt = await stack.publicClient.waitForTransactionReceipt({
      hash: handleHash,
    });
    const opEvents = parseEventLogs({
      abi: entryPointV07Abi,
      logs: receipt.logs,
      eventName: "UserOperationEvent",
    });
    expect(opEvents.length).toBe(1);
    expect(opEvents[0].args.success).toBe(true);

    // The money assertion: sponsored under the ROTATED key's epoch 1.
    const sponsorships = parseEventLogs({
      abi: shrincsPaymasterAbi,
      logs: receipt.logs,
      eventName: "SponsorshipVerified",
    });
    expect(sponsorships.length).toBe(1);
    expect(Number(sponsorships[0].args.leaf)).toBe(leaf);
    expect(BigInt(sponsorships[0].args.keyVersion)).toBe(1n);

    const recipientAfter = await stack.publicClient.getBalance({
      address: RECIPIENT,
    });
    expect(recipientAfter - recipientBefore).toBe(value);
  }, 240_000);

  // ── (k) front-run rejection ──────────────────────────────────────────
  it("k. front-running a victim's commitment with a different owner reverts IdentityMismatch", async () => {
    const victimSeed = 0xb0;
    const victimIndex = victimSeed;
    const victimErc1271Index = victimSeed ^ 0xff;
    const signer = await makeShrincsSigner(victimSeed);
    const mainKey = signer.recoverKeyPair(victimIndex, {
      maxSignatures: MAX_SIGS,
    });
    const erc1271Key = signer.recoverKeyPair(victimErc1271Index, {
      maxSignatures: MAX_SIGS,
    });
    const statefulC = mainKey.publicKeyCommitment;
    const statelessC = erc1271Key.publicKeyCommitment;
    const victimOwner = DEFAULT_ACCOUNT.address;
    const victimCommitment = v1Commitment(statefulC, statelessC, victimOwner);

    const initPayload = encodeInitPayload({
      mainBundle: mainKey.publicKey,
      erc1271Commitment: statelessC,
    });

    // Fixture vets exactly one impl; index 0 is that entry.
    const vettedCount = await stack.publicClient.readContract({
      address: stack.factoryAddress,
      abi: walletFactoryAbi,
      functionName: "getVettedCodeCount",
    });
    expect(vettedCount).toBe(1n);
    const index = 0n;

    const creationFee = await stack.publicClient.readContract({
      address: stack.factoryAddress,
      abi: walletFactoryAbi,
      functionName: "creationFee",
    });

    const ATTACKER_OWNER =
      "0x0000000000000000000000000000000000000bad" as Address;
    expect(getAddress(ATTACKER_OWNER)).not.toBe(getAddress(victimOwner));

    const deploy = (owner: Address) =>
      stack.walletClient.writeContract({
        chain: foundry,
        address: stack.factoryAddress,
        abi: walletFactoryAbi,
        functionName: "deploySpecificWalletProxy",
        args: [victimCommitment, index, owner, initPayload],
        value: creationFee,
        account: stack.account,
      });

    // Attacker occupies the victim's commitment with a different owner — initialize
    // recomputes v1CommitmentTail(..., ATTACKER_OWNER) and reverts IdentityMismatch.
    let caught: unknown = null;
    try {
      await deploy(ATTACKER_OWNER);
    } catch (e) {
      caught = e;
    }
    expect(caught).not.toBeNull();
    const identityMismatch = toFunctionSelector("IdentityMismatch()");
    expect(caught).toBeInstanceOf(BaseError);
    const reverted = (caught as BaseError).walk(
      (e) => e instanceof ContractFunctionRevertedError
    ) as ContractFunctionRevertedError | null;
    expect(reverted?.raw?.slice(0, 10)).toBe(identityMismatch);

    // Positive control: the same deploy with the bound owner succeeds.
    const hash = await deploy(victimOwner);
    const receipt = await stack.publicClient.waitForTransactionReceipt({
      hash,
    });
    expect(receipt.status).toBe("success");
  }, 120_000);
});
