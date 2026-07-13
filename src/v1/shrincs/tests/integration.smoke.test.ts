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
  getAddress,
  parseEther,
  parseEventLogs,
  toHex,
} from "viem";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

import { entryPointV07Abi } from "../../abi/EntryPointV07.js";
import { CANONICAL_ENTRYPOINT_V07 } from "../../addresses.js";
import { shrincsWalletAbi } from "../abi/ShrincsWallet.js";
import { shrincsPaymasterAbi } from "../abi/ShrincsPaymaster.js";
import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import { Erc1271ValidationResult, StaleStatefulLeafError } from "../errors.js";
import { ShrincsPaymasterClient } from "../shrincsPaymasterClient.js";
import {
  SHRINCS_ANVIL_PORTS,
  type ShrincsAnvilStack,
  createFreshShrincsWallet,
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
const MAX_SIGS = 4;

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
    const { client, signer, vaultId, walletAddress } =
      await createFreshShrincsWallet(stack, seedByte, {
        maxSignatures: MAX_SIGS,
      });

    const state = await client.getWalletState();
    expect(getAddress(state.owner)).toBe(getAddress(stack.account.address));
    expect(state.maxSignatures).toBe(MAX_SIGS);
    expect(state.statefulLeavesUsed).toBe(0);
    expect(state.remainingStatefulSignatures).toBe(MAX_SIGS);

    // Commitment installed on-chain reproduces from the signer.
    const mainKey = signer.recoverKeyPair(vaultId, { maxSignatures: MAX_SIGS });
    expect(state.shrincsPublicKeyCommitment.toLowerCase()).toBe(
      mainKey.publicKeyCommitment.toLowerCase()
    );

    // getShrincsWallet resolves the same address and validates the commitment.
    const factory = makeShrincsFactoryClient(stack);
    const resolved = await factory.getShrincsWallet(vaultId, signer);
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
    expect(await client.isStatefulLeafUsed(1)).toBe(true);
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
    expect(Number(leaves1[0].args.leaf)).toBe(1);

    const r2 = await client.execute({ target: RECIPIENT, value: parseEther("0.1") });
    const leaves2 = parseEventLogs({
      abi: shrincsWalletAbi,
      logs: r2.logs,
      eventName: "StatefulSignatureVerified",
    });
    expect(leaves2.length).toBe(1);
    expect(Number(leaves2[0].args.leaf)).toBe(2);

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

    // Force leaf 1, succeed.
    await client.execute({ target: RECIPIENT, value: parseEther("0.05") }, { leaf: 1 });
    expect(await client.isStatefulLeafUsed(1)).toBe(true);

    // Reuse leaf 1 — must revert. The decoded error should be StaleStatefulLeaf.
    let caught: unknown = null;
    try {
      await client.execute(
        { target: RECIPIENT, value: parseEther("0.05") },
        { leaf: 1 }
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
    const { client, signer, erc1271VaultId } = await createFreshShrincsWallet(
      stack,
      0x50,
      { maxSignatures: MAX_SIGS }
    );

    // The ERC-1271 verifier key was installed at creation under erc1271VaultId.
    const state = await client.getWalletState();
    const erc1271KeyPair = signer.recoverKeyPair(erc1271VaultId, {
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
    const operatorVaultId = toHex(new Uint8Array(32).fill(operatorSeed));
    const verifierKey = operator.recoverKeyPair(operatorVaultId, {
      maxSignatures: MAX_SIGS,
    });

    // Initialize the paymaster with the operator's verifier commitment, then
    // fund its EntryPoint deposit + stake so it can sponsor.
    await initializePaymaster(stack, {
      owner: stack.account.address,
      commitment: verifierKey.publicKeyCommitment,
      maxSignatures: MAX_SIGS,
      hashSuite: HASH_SUITE_KECCAK_256,
    });

    const pmClient = new ShrincsPaymasterClient({
      paymasterAddress: stack.paymasterProxy,
      publicClient: stack.publicClient,
      walletClient: stack.walletClient,
      signer: operator,
      vaultId: operatorVaultId,
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

    let userOp = walletClient.buildExecuteUserOp({
      target: RECIPIENT,
      value,
      data: "0x",
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
});
