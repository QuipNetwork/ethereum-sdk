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
import { type Address, toHex, zeroAddress } from "viem";

import { QuipSigner } from "../signer.js";
import { createInMemoryBurnSet } from "../burnSet.js";
import { WOTSPlusImplementationClient, KeyType } from "../walletClient.js";
import {
  DuplicateKeyError,
  EmptyKeysError,
  KeyAlreadyBurnedError,
  PartialMulticallResultError,
  UnknownKeyError,
} from "../errors.js";
import {
  type WinternitzAddress,
  MAX_KEYS,
} from "../wotsCodec.js";
import {
  ANVIL_PORTS,
  type AnvilStack,
  createFreshWallet,
  setupAnvilStack,
  stopAnvilStack,
} from "./utils/anvilFixture.js";
import { foundry } from "viem/chains";

let stack: AnvilStack;

beforeAll(async () => {
  stack = await setupAnvilStack({ port: ANVIL_PORTS.hardening });
}, 60_000);

afterAll(async () => {
  await stopAnvilStack(stack);
}, 10_000);

// ─── Tests ──────────────────────────────────────────────────────────

describe("Phase 4.5 — pre-flight key-batch validation", () => {
  test("replaceTxKeys with empty oldKeys throws EmptyKeysError synchronously", async () => {
    const { client } = await createFreshWallet(stack, 0x10);
    await expect(client.replaceTxKeys([])).rejects.toBeInstanceOf(
      EmptyKeysError
    );
  });

  test("replaceTxKeys with within-batch duplicate throws DuplicateKeyError synchronously", async () => {
    const { client } = await createFreshWallet(stack, 0x11);
    const keyset = await client.getKeyset(KeyType.Transaction);
    // Pass the same currently-installed tx key twice — the SDK's pre-flight
    // batch validation rejects within-batch duplicates before signing.
    await expect(
      client.replaceTxKeys([keyset[5], keyset[5]])
    ).rejects.toBeInstanceOf(DuplicateKeyError);
  });
});

describe("Phase 4.5 — burned-key tracking on broadcast", () => {
  test("successful executeWithPayload marks the signing key burned", async () => {
    const { client, signer, vaultId, isBurned } = await createFreshWallet(
      stack,
      0x20
    );

    const head = await client.getHeadTransactionKey();
    expect(isBurned(head.publicSeed)).toBe(false);

    // Pure rotation: target=zero, value=0, data="0x". The fee still
    // applies but is zero on the unconfigured factory.
    await client.executeWithPayload(zeroAddress, 0n, "0x");

    expect(isBurned(head.publicSeed)).toBe(true);
    // Sanity: signer.sign with a fresh (never-burned) key works.
    const dummySeed = toHex(new Uint8Array(32).fill(0xfe));
    await expect(
      signer.sign(toHex(new Uint8Array(32)), vaultId, dummySeed)
    ).resolves.not.toThrow();
  }, 30_000);

  test("retry with the same key throws KeyAlreadyBurnedError; retry with a different key succeeds", async () => {
    const { client, isBurned } = await createFreshWallet(stack, 0x21);

    const keyset = await client.getKeyset(KeyType.Transaction);
    expect(keyset.length).toBe(MAX_KEYS);
    const firstKey = keyset[0];
    const secondKey = keyset[1];

    // First op: signs with firstKey (head), broadcasts, burns it.
    await client.executeWithPayload(zeroAddress, 0n, "0x", {
      signWithKey: firstKey,
    });
    expect(isBurned(firstKey.publicSeed)).toBe(true);

    // Retry with the same (now-burned) key → consume refuses. The first
    // key has been rotated out of the keyset on chain too, so this could
    // also surface as `UnknownKeyError` from the pre-flight `isKey`
    // check that happens BEFORE the consume call. Accept either —
    // both correctly refuse the retry.
    let caught: unknown = null;
    try {
      await client.executeWithPayload(zeroAddress, 0n, "0x", {
        signWithKey: firstKey,
      });
    } catch (e) {
      caught = e;
    }
    expect(
      caught instanceof KeyAlreadyBurnedError ||
        caught instanceof UnknownKeyError
    ).toBe(true);

    // Retry with a different key from the keyset succeeds.
    await client.executeWithPayload(zeroAddress, 0n, "0x", {
      signWithKey: secondKey,
    });
    expect(isBurned(secondKey.publicSeed)).toBe(true);
  }, 60_000);

  test("head burned in-session — default-key executeWithPayload throws KeyAlreadyBurnedError; retry with signWithKey succeeds", async () => {
    const { client, isBurned, markBurned } = await createFreshWallet(
      stack,
      0x22
    );
    const keyset = await client.getKeyset(KeyType.Transaction);
    const headBefore = await client.getHeadTransactionKey();

    // Pre-burn the head locally (no broadcast). On the next default-keyed
    // write, pickTransactionKeyPair will pick the (still-live) head; the
    // signer's consume then refuses.
    markBurned(headBefore.publicSeed);
    expect(isBurned(headBefore.publicSeed)).toBe(true);

    await expect(
      client.executeWithPayload(zeroAddress, 0n, "0x")
    ).rejects.toBeInstanceOf(KeyAlreadyBurnedError);

    // Retry with an explicit unburned key from the keyset succeeds. Pick
    // any keyset entry that isn't the burned head.
    const alternative = keyset.find(
      (k) => k.publicSeed !== headBefore.publicSeed
    );
    if (!alternative) throw new Error("expected at least 2 transaction keys");
    await client.executeWithPayload(zeroAddress, 0n, "0x", {
      signWithKey: alternative,
    });
    expect(isBurned(alternative.publicSeed)).toBe(true);
  }, 30_000);

  test("signWithKey not in the live keyset throws UnknownKeyError synchronously and does NOT burn the key", async () => {
    const { client, isBurned } = await createFreshWallet(stack, 0x24);

    // A fabricated key not present in the wallet's transaction keyset.
    // Pre-flight `isKey` in `pickTransactionKeyPair` must reject this
    // before `quipSigner.sign(...)` runs, so the publicSeed stays
    // unburned. Without the pre-check the on-chain call would revert
    // `UnknownKey` AFTER the SDK had already produced (and burned) a
    // WOTS+ signature against a guaranteed-revert payload.
    const stale: WinternitzAddress = {
      publicSeed: toHex(new Uint8Array(32).fill(0xee)),
      publicKeyHash: toHex(new Uint8Array(32).fill(0xff)),
    };
    expect(isBurned(stale.publicSeed)).toBe(false);

    await expect(
      client.executeWithPayload(zeroAddress, 0n, "0x", {
        signWithKey: stale,
      })
    ).rejects.toBeInstanceOf(UnknownKeyError);

    // Critical: the WOTS+ key MUST NOT be marked burned. A real-life
    // misconfiguration (passing a stale key) shouldn't waste a key.
    expect(isBurned(stale.publicSeed)).toBe(false);
  });
});

describe("Phase 4.5 — multicall partial-failure surfacing", () => {
  test("getWalletState against a no-code address throws PartialMulticallResultError", async () => {
    // Point a WOTSPlusImplementationClient at an address with no code. The factory +
    // impl are deployed, but this random EOA address has no WOTSPlusImplementation.
    const signer = new QuipSigner(
      new Uint8Array(32).fill(0x30),
      createInMemoryBurnSet().consume
    );
    const noCodeAddr = "0xdeAdbEefdEAdbeefdEadbEEFdeadbeEFdEaDbeef" as Address;
    const client = new WOTSPlusImplementationClient(
      signer,
      toHex(new Uint8Array(32).fill(0x30)),
      noCodeAddr,
      stack.publicClient,
      stack.walletClient,
      stack.account.address,
      foundry.id
    );

    let caught: unknown = null;
    try {
      // Multicall against a no-code address surfaces a per-sub-call failure
      // set; PartialMulticallResultError aggregates them.
      await client.getWalletState();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(PartialMulticallResultError);
    const err = caught as PartialMulticallResultError;
    expect(err.failures.length).toBeGreaterThan(0);
    // Each failure should carry a non-empty label
    for (const f of err.failures) {
      expect(typeof f.label).toBe("string");
      expect(f.label.length).toBeGreaterThan(0);
      expect(f.error).toBeInstanceOf(Error);
    }
  });

  test("getKeyset against a no-code address throws", async () => {
    // Point at an address that has code but does NOT implement `getKeyset`
    // (the factory). Single `eth_call` against the missing function reverts.
    const signer = new QuipSigner(
      new Uint8Array(32).fill(0x31),
      createInMemoryBurnSet().consume
    );
    const client = new WOTSPlusImplementationClient(
      signer,
      toHex(new Uint8Array(32).fill(0x31)),
      stack.factoryAddress,
      stack.publicClient,
      stack.walletClient,
      stack.account.address,
      foundry.id
    );

    await expect(client.getKeyset(KeyType.Transaction)).rejects.toThrow();
  });
});
