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
import { describe, it, expect } from "@jest/globals";
import { type Hex, toHex } from "viem";

import { QuipSigner } from "../signer.js";
import { createInMemoryBurnSet } from "../burnSet.js";
import {
  KeyAlreadyBurnedError,
  KeyDerivationSelfTestError,
} from "../errors.js";

const QUANTUM_SECRET = new Uint8Array(32).fill(0xab);
const VAULT_ID: Hex = toHex(new Uint8Array(32).fill(0x01));
const MESSAGE: Hex = toHex(new Uint8Array(32).fill(0x77));

describe("QuipSigner burned-key tracking via injected consume", () => {
  it("sign succeeds when key is not burned", () => {
    const burnSet = createInMemoryBurnSet();
    const signer = new QuipSigner(QUANTUM_SECRET, burnSet.consume);
    const kp = signer.generateKeyPair(VAULT_ID);
    const sig = signer.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
    expect(sig.length).toBe(67);
    for (const el of sig) {
      expect(el.length).toBe(2 + 64);
    }
  });

  it("sign records the burn via the injected consume (second sign throws)", () => {
    const burnSet = createInMemoryBurnSet();
    const signer = new QuipSigner(QUANTUM_SECRET, burnSet.consume);
    const kp = signer.generateKeyPair(VAULT_ID);
    signer.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
    const otherMessage: Hex = toHex(new Uint8Array(32).fill(0xaa));
    expect(() =>
      signer.sign(otherMessage, VAULT_ID, kp.publicKey.publicSeed)
    ).toThrow(KeyAlreadyBurnedError);
  });

  it("KeyAlreadyBurnedError carries the publicSeed", () => {
    const burnSet = createInMemoryBurnSet();
    const signer = new QuipSigner(QUANTUM_SECRET, burnSet.consume);
    const kp = signer.generateKeyPair(VAULT_ID);
    // Pre-burn via the burn set directly.
    burnSet.consume(kp.publicKey.publicSeed);
    try {
      signer.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
      throw new Error("expected sign to throw");
    } catch (e) {
      expect(e).toBeInstanceOf(KeyAlreadyBurnedError);
      if (e instanceof KeyAlreadyBurnedError) {
        expect(e.publicSeed).toBe(kp.publicKey.publicSeed);
        expect(e.code).toBe("KEY_ALREADY_BURNED");
      }
    }
  });

  it("burning one key does not affect another", () => {
    const burnSet = createInMemoryBurnSet();
    const signer = new QuipSigner(QUANTUM_SECRET, burnSet.consume);
    const a = signer.generateKeyPair(VAULT_ID);
    const b = signer.generateKeyPair(VAULT_ID);
    burnSet.consume(a.publicKey.publicSeed);
    // Signing with b still works.
    const sig = signer.sign(MESSAGE, VAULT_ID, b.publicKey.publicSeed);
    expect(sig.length).toBe(67);
    // Signing with a throws.
    expect(() =>
      signer.sign(MESSAGE, VAULT_ID, a.publicKey.publicSeed)
    ).toThrow(KeyAlreadyBurnedError);
  });

  it("each signer can be wired to its own burn set (independent state)", () => {
    const burnSetA = createInMemoryBurnSet();
    const burnSetB = createInMemoryBurnSet();
    const signerA = new QuipSigner(QUANTUM_SECRET, burnSetA.consume);
    const signerB = new QuipSigner(QUANTUM_SECRET, burnSetB.consume);
    const kp = signerA.generateKeyPair(VAULT_ID);
    signerA.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
    // signerA's burn was recorded in burnSetA; burnSetB is untouched, so
    // signerB can still sign with the same seed.
    const sig = signerB.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
    expect(sig.length).toBe(67);
  });

  it("two signers sharing a burn set share burn state", () => {
    const burnSet = createInMemoryBurnSet();
    const signerA = new QuipSigner(QUANTUM_SECRET, burnSet.consume);
    const signerB = new QuipSigner(QUANTUM_SECRET, burnSet.consume);
    const kp = signerA.generateKeyPair(VAULT_ID);
    signerA.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
    // The burn surfaces through signerB because both signers share the
    // same consume function.
    expect(() =>
      signerB.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed)
    ).toThrow(KeyAlreadyBurnedError);
  });
});

describe("QuipSigner consume runs BEFORE the WOTS+ signature", () => {
  it("a failing consume short-circuits before any signature exists", () => {
    const failing = (_publicSeed: Hex): void => {
      throw new KeyAlreadyBurnedError(_publicSeed);
    };
    const signer = new QuipSigner(QUANTUM_SECRET, failing);
    const kp = signer.generateKeyPair(VAULT_ID);
    expect(() =>
      signer.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed)
    ).toThrow(KeyAlreadyBurnedError);
  });

  it("consume is invoked exactly once per sign() call", () => {
    let calls = 0;
    const tracker = (_publicSeed: Hex): void => {
      calls += 1;
    };
    const signer = new QuipSigner(QUANTUM_SECRET, tracker);
    const kp = signer.generateKeyPair(VAULT_ID);
    signer.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
    expect(calls).toBe(1);
    signer.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
    expect(calls).toBe(2);
  });
});

describe("QuipSigner key-derivation self-test", () => {
  it("generateKeyPair returns a keypair whose self-test passed (real path)", () => {
    const burnSet = createInMemoryBurnSet();
    const signer = new QuipSigner(QUANTUM_SECRET, burnSet.consume);
    // Self-test runs inside generateKeyPair; no throw means it passed.
    const kp = signer.generateKeyPair(VAULT_ID);
    expect(kp.publicKey.publicSeed.length).toBe(2 + 64);
  });

  it("recoverKeyPair runs the self-test on every recovery", () => {
    const burnSet = createInMemoryBurnSet();
    const signer = new QuipSigner(QUANTUM_SECRET, burnSet.consume);
    const kp = signer.generateKeyPair(VAULT_ID);
    // Recovery should succeed (self-test passes on a previously-validated
    // derivation).
    const recovered = signer.recoverKeyPair(VAULT_ID, kp.publicKey.publicSeed);
    expect(recovered.publicKey.publicSeed).toBe(kp.publicKey.publicSeed);
    expect(recovered.publicKey.publicKeyHash).toBe(kp.publicKey.publicKeyHash);
  });

  it("self-test does NOT call the burn-set consume (sentinel sig is local-only)", () => {
    let calls = 0;
    const tracker = (_publicSeed: Hex): void => {
      calls += 1;
    };
    const signer = new QuipSigner(QUANTUM_SECRET, tracker);
    // generateKeyPair runs the self-test internally. If the self-test
    // signed via the QuipSigner.sign() path, consume would fire here.
    // It must not — the sentinel sig uses the raw WOTSPlus path.
    const _kp = signer.generateKeyPair(VAULT_ID);
    expect(calls).toBe(0);
    // And a real sign() afterwards still works (the key is not burned).
    const sig = signer.sign(MESSAGE, VAULT_ID, _kp.publicKey.publicSeed);
    expect(sig.length).toBe(67);
    expect(calls).toBe(1);
  });

  it("self-test throws KeyDerivationSelfTestError when WOTSPlus.verify fails", () => {
    const burnSet = createInMemoryBurnSet();
    const signer = new QuipSigner(QUANTUM_SECRET, burnSet.consume);
    // Reach into the private WOTS+ instance and force verify to return
    // false. Mirrors a library bug or memory corruption — the public
    // surface should refuse to hand back the keypair.
    const wots = (signer as unknown as { wots: { verify: () => boolean } }).wots;
    const originalVerify = wots.verify;
    wots.verify = (): boolean => false;
    try {
      expect(() => signer.generateKeyPair(VAULT_ID)).toThrow(
        KeyDerivationSelfTestError
      );
    } finally {
      wots.verify = originalVerify;
    }
  });

  it("KeyDerivationSelfTestError carries the publicSeed and code", () => {
    const burnSet = createInMemoryBurnSet();
    const signer = new QuipSigner(QUANTUM_SECRET, burnSet.consume);
    const wots = (signer as unknown as { wots: { verify: () => boolean } }).wots;
    const originalVerify = wots.verify;
    wots.verify = (): boolean => false;
    try {
      signer.generateKeyPair(VAULT_ID);
      throw new Error("expected generateKeyPair to throw");
    } catch (e) {
      expect(e).toBeInstanceOf(KeyDerivationSelfTestError);
      if (e instanceof KeyDerivationSelfTestError) {
        expect(e.code).toBe("KEY_DERIVATION_SELFTEST_FAILED");
        expect(e.publicSeed.length).toBe(2 + 64);
      }
    } finally {
      wots.verify = originalVerify;
    }
  });
});

describe("createInMemoryBurnSet case normalization", () => {
  it("treats 0xABCD… and 0xabcd… as the same burn record", () => {
    const burnSet = createInMemoryBurnSet();
    const seedLower =
      "0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" as Hex;
    const seedUpper = seedLower.toUpperCase() as Hex;

    burnSet.consume(seedLower);
    expect(() => burnSet.consume(seedUpper)).toThrow(KeyAlreadyBurnedError);
  });

  it("treats mixed-case as the same burn record", () => {
    const burnSet = createInMemoryBurnSet();
    const seedA =
      "0xAbCdEf01234567890abcdef01234567890ABCDEF01234567890abcdef01234567" as Hex;
    const seedB =
      "0xaBcDeF01234567890ABCDEF01234567890abcdef01234567890ABCDEF01234567" as Hex;

    burnSet.consume(seedA);
    expect(() => burnSet.consume(seedB)).toThrow(KeyAlreadyBurnedError);
  });

  it("KeyAlreadyBurnedError carries the original-case publicSeed the caller passed (not the lowercased internal form)", () => {
    const burnSet = createInMemoryBurnSet();
    const seedLower =
      "0x1111111111111111111111111111111111111111111111111111111111111111" as Hex;
    const seedUpper = seedLower.toUpperCase() as Hex;

    burnSet.consume(seedLower);
    try {
      burnSet.consume(seedUpper);
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(KeyAlreadyBurnedError);
      if (e instanceof KeyAlreadyBurnedError) {
        // The error reports back whichever case the offending caller supplied.
        expect(e.publicSeed).toBe(seedUpper);
      }
    }
  });

  it("clear() drops every recorded burn (test-only escape hatch)", () => {
    const burnSet = createInMemoryBurnSet();
    const seed =
      "0x2222222222222222222222222222222222222222222222222222222222222222" as Hex;
    burnSet.consume(seed);
    expect(() => burnSet.consume(seed)).toThrow(KeyAlreadyBurnedError);
    burnSet.clear();
    // After clear the same seed is re-consumable.
    expect(() => burnSet.consume(seed)).not.toThrow();
  });
});
