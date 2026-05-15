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
  parseKeyReplaced,
  parseKeyRotated,
  parseKeyRotationOnly,
  parseKeysAdded,
  parseKeysRefreshed,
  parseQuipCreated,
  parseWalletInitialized,
  parseWalletReceipt,
} from "../events.js";
import {
  TRANSACTION_KEY_INIT_AMOUNT,
  RECOVERY_KEY_AMOUNT,
} from "../wotsCodec.js";
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
  test("parseKeysAdded decodes addKeys receipt", async () => {
    const { client, signer, vaultId } = await createFreshWallet(stack, 0xc4);
    // Recovery keyset starts at full capacity (10). Use the Verification
    // keyset which starts empty.
    const newKeys = [
      signer.generateKeyPair(toHex(vaultId)).publicKey,
      signer.generateKeyPair(toHex(vaultId)).publicKey,
    ];
    const receipt = await client.addKeys(KeyType.Verification, newKeys);
    const events = parseKeysAdded(receipt);
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe(KeyType.Verification);
    expect(events[0].count).toBe(2n);
    // KeyRotated also emitted (the signing tx key rotated).
    expect(parseKeyRotated(receipt)).toHaveLength(1);
  }, 30_000);

  test("parseKeysRefreshed decodes refreshKeys receipt", async () => {
    const { client, signer, vaultId } = await createFreshWallet(stack, 0xc5);
    const newRecovery = Array.from({ length: 3 }, () =>
      signer.generateKeyPair(toHex(vaultId)).publicKey
    );
    const receipt = await client.refreshKeys(KeyType.Recovery, newRecovery);
    const events = parseKeysRefreshed(receipt);
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe(KeyType.Recovery);
  }, 30_000);

  test("parseKeyReplaced decodes replaceKeyAt receipt", async () => {
    const { client, signer, vaultId } = await createFreshWallet(stack, 0xc6);
    const newKey = signer.generateKeyPair(toHex(vaultId)).publicKey;
    const receipt = await client.replaceKeyAt(KeyType.Recovery, 0n, newKey);
    const events = parseKeyReplaced(receipt);
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe(KeyType.Recovery);
    expect(events[0].index).toBe(0n);
    expect(events[0].newKey.publicSeed).toBe(newKey.publicSeed);
  }, 30_000);
});

describe("parseWalletInitialized", () => {
  test("decodes the WalletInitialized log from a fresh wallet's creation receipt", async () => {
    const { creationReceipt, transactionKeys } = await createFreshWallet(
      stack,
      0xc7
    );
    const events = parseWalletInitialized(creationReceipt);
    expect(events).toHaveLength(1);
    expect(events[0].owner.toLowerCase()).toBe(
      stack.account.address.toLowerCase()
    );
    expect(events[0].transactionKeys).toHaveLength(TRANSACTION_KEY_INIT_AMOUNT);
    expect(events[0].recoveryKeys).toHaveLength(RECOVERY_KEY_AMOUNT);
    expect(events[0].transactionKeys[0].publicSeed).toBe(
      transactionKeys[0].publicSeed
    );
  }, 30_000);
});
