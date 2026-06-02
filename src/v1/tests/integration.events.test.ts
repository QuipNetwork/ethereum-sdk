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
import { describe, test, expect, beforeAll, afterAll } from "@jest/globals";
import { toHex, zeroAddress } from "viem";

import { KeyType } from "../walletClient.js";
import {
  parseExecutionSucceeded,
  parseKeyRotated,
  parseKeyRotationOnly,
  parseKeysReplaced,
  parseKeysetReset,
  parseQuipCreated,
  parseWalletInitialized,
  parseWalletReceipt,
} from "../events.js";
import {
  ANVIL_PORTS,
  type AnvilStack,
  createFreshWallet,
  setupAnvilStack,
  stopAnvilStack,
} from "./utils/anvilFixture.js";

let stack: AnvilStack;

beforeAll(async () => {
  stack = await setupAnvilStack({
    port: ANVIL_PORTS.events,
    deployEntryPoint: false, // events tests don't exercise the 4337 path
  });
}, 60_000);

afterAll(async () => {
  await stopAnvilStack(stack);
}, 10_000);

describe("Factory event parsers", () => {
  test("parseQuipCreated decodes deployLatestWalletProxy receipt", async () => {
    const { creationReceipt, walletAddress, disasterKey } =
      await createFreshWallet(stack, 0xc0);
    const events = parseQuipCreated(creationReceipt);
    expect(events).toHaveLength(1);
    expect(events[0].creator.toLowerCase()).toBe(
      stack.account.address.toLowerCase()
    );
    expect(events[0].quip.toLowerCase()).toBe(walletAddress.toLowerCase());
    expect(events[0].disasterRecoveryKey.publicSeed).toBe(
      disasterKey.publicSeed
    );
  }, 30_000);
});

describe("Wallet event parsers — execution path", () => {
  test("parseWalletReceipt → 'executed' on successful ETH transfer", async () => {
    const { client } = await createFreshWallet(stack, 0xc1);
    const recipient = "0x000000000000000000000000000000000000DEAd" as const;
    const receipt = await client.executeWithPayload(recipient, 100n, "0x");
    const result = parseWalletReceipt(receipt);
    if (result === null) throw new Error("expected non-null");
    if (result.kind !== "executed")
      throw new Error(`expected executed, got ${result.kind}`);
    expect(result.target.toLowerCase()).toBe(recipient.toLowerCase());
    expect(result.value).toBe(100n);
    // ExecutionSucceeded + KeyRotated both present.
    expect(parseExecutionSucceeded(receipt)).toHaveLength(1);
    expect(parseKeyRotated(receipt)).toHaveLength(1);
    expect(result.rotation.oldKey.publicSeed).not.toBe(
      result.rotation.newKey.publicSeed
    );
  }, 30_000);

  test("parseWalletReceipt → 'rotation-only' for execute(zero, 0, '0x')", async () => {
    const { client } = await createFreshWallet(stack, 0xc2);
    const receipt = await client.executeWithPayload(zeroAddress, 0n, "0x");
    const result = parseWalletReceipt(receipt);
    if (result === null) throw new Error("expected non-null");
    expect(result.kind).toBe("rotation-only");
    expect(parseKeyRotationOnly(receipt)).toHaveLength(1);
    expect(parseExecutionSucceeded(receipt)).toHaveLength(0);
  }, 30_000);

  // Note: the contract does not currently emit `ExecutionReverted` —
  // `LibCall.callContract` bubbles inner reverts so the whole `execute(bytes)`
  // reverts together. The event is declared in `IQuipWallet.sol` as
  // future-ready (for an ERC-4337 path where the wallet absorbs inner reverts
  // while still committing key rotation). The parser + `decodedReason` chain
  // is covered by `src/events.test.ts`; no live integration trigger exists
  // until the contract starts emitting it.
});

describe("Wallet event parsers — key management", () => {
  test("parseKeysReplaced decodes replaceTxKeys receipt", async () => {
    const { client } = await createFreshWallet(stack, 0xc4);
    const txKeyset = await client.getKeyset(KeyType.Transaction);
    // Pick two tx keys that won't be the signing head: index 5 and 6 are
    // safely off the head-rotation path under the SDK's default picker.
    const oldKeys = [txKeyset[5], txKeyset[6]];
    const receipt = await client.replaceTxKeys(oldKeys);
    const events = parseKeysReplaced(receipt);
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe(KeyType.Transaction);
    expect(events[0].signingKind).toBe(KeyType.Transaction);
    expect(events[0].oldKeys.length).toBe(2);
    expect(events[0].newKeys.length).toBe(2);
    // KeyRotated also emitted (the signing tx key rotated).
    expect(parseKeyRotated(receipt)).toHaveLength(1);
  }, 30_000);

  test("parseKeysetReset decodes resetRecoveryKeys receipt", async () => {
    const { client } = await createFreshWallet(stack, 0xc5);
    const receipt = await client.resetRecoveryKeys();
    const events = parseKeysetReset(receipt);
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe(KeyType.Recovery);
    expect(events[0].signingKind).toBe(KeyType.Transaction);
    expect(events[0].newKeys.length).toBe(10);
  }, 30_000);

  test("parseKeysetReset decodes resetVerificationKeys receipt", async () => {
    const { client } = await createFreshWallet(stack, 0xc6);
    const receipt = await client.resetVerificationKeys();
    const events = parseKeysetReset(receipt);
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe(KeyType.Verification);
    expect(events[0].signingKind).toBe(KeyType.Transaction);
  }, 30_000);
});

describe("parseWalletInitialized", () => {
  test("decodes the WalletInitialized log from a fresh wallet's creation receipt", async () => {
    const { creationReceipt } = await createFreshWallet(stack, 0xc7);
    const events = parseWalletInitialized(creationReceipt);
    expect(events).toHaveLength(1);
    expect(events[0].owner.toLowerCase()).toBe(
      stack.account.address.toLowerCase()
    );
    // Hash-shape WalletInitialized event: the three keyset hashes must all be
    // non-zero (`keccak256(abi.encode([10]))` of any non-empty input is
    // non-zero), and distinct from each other under the always-10 invariant
    // (different keyset contents → different hashes).
    expect(events[0].transactionKeysHash).not.toBe(
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    expect(events[0].recoveryKeysHash).not.toBe(
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    expect(events[0].verificationKeysHash).not.toBe(
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    expect(events[0].transactionKeysHash).not.toBe(
      events[0].recoveryKeysHash
    );
  }, 30_000);
});
