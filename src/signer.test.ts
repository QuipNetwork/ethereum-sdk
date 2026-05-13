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
import { toHex } from "viem";

import { QuipSigner } from "./signer.js";
import { KeyAlreadyBurnedError } from "./errors.js";

const QUANTUM_SECRET = new Uint8Array(32).fill(0xab);
const VAULT_ID = new Uint8Array(32).fill(0x01);
const MESSAGE = new Uint8Array(32).fill(0x77);

describe("QuipSigner burned-key tracking", () => {
  it("sign succeeds when key is not burned", () => {
    const signer = new QuipSigner(QUANTUM_SECRET);
    const kp = signer.generateKeyPair(VAULT_ID);
    const sig = signer.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
    expect(sig.length).toBe(67);
  });

  it("sign auto-burns the key (signing the same key twice throws)", () => {
    const signer = new QuipSigner(QUANTUM_SECRET);
    const kp = signer.generateKeyPair(VAULT_ID);
    // First sign succeeds and marks the key burned.
    signer.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
    expect(signer.isBurned(kp.publicKey.publicSeed)).toBe(true);
    // Second sign with the same key — even on a different message — fails.
    expect(() =>
      signer.sign(new Uint8Array(32).fill(0xaa), VAULT_ID, kp.publicKey.publicSeed)
    ).toThrow(KeyAlreadyBurnedError);
  });

  it("isBurned returns false for a never-marked key", () => {
    const signer = new QuipSigner(QUANTUM_SECRET);
    const kp = signer.generateKeyPair(VAULT_ID);
    expect(signer.isBurned(kp.publicKey.publicSeed)).toBe(false);
  });

  it("isBurned returns true after markBurned (Uint8Array input)", () => {
    const signer = new QuipSigner(QUANTUM_SECRET);
    const kp = signer.generateKeyPair(VAULT_ID);
    signer.markBurned(kp.publicKey.publicSeed);
    expect(signer.isBurned(kp.publicKey.publicSeed)).toBe(true);
  });

  it("isBurned returns true after markBurned (Hex input)", () => {
    const signer = new QuipSigner(QUANTUM_SECRET);
    const kp = signer.generateKeyPair(VAULT_ID);
    const seedHex = toHex(kp.publicKey.publicSeed);
    signer.markBurned(seedHex);
    expect(signer.isBurned(seedHex)).toBe(true);
    expect(signer.isBurned(kp.publicKey.publicSeed)).toBe(true);
  });

  it("sign throws KeyAlreadyBurnedError on a burned key", () => {
    const signer = new QuipSigner(QUANTUM_SECRET);
    const kp = signer.generateKeyPair(VAULT_ID);
    signer.markBurned(kp.publicKey.publicSeed);
    expect(() =>
      signer.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed)
    ).toThrow(KeyAlreadyBurnedError);
  });

  it("KeyAlreadyBurnedError carries the publicSeed", () => {
    const signer = new QuipSigner(QUANTUM_SECRET);
    const kp = signer.generateKeyPair(VAULT_ID);
    const seedHex = toHex(kp.publicKey.publicSeed);
    signer.markBurned(kp.publicKey.publicSeed);
    try {
      signer.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
      throw new Error("expected sign to throw");
    } catch (e) {
      expect(e).toBeInstanceOf(KeyAlreadyBurnedError);
      if (e instanceof KeyAlreadyBurnedError) {
        expect(e.publicSeed).toBe(seedHex);
        expect(e.code).toBe("KEY_ALREADY_BURNED");
      }
    }
  });

  it("markBurned is idempotent", () => {
    const signer = new QuipSigner(QUANTUM_SECRET);
    const kp = signer.generateKeyPair(VAULT_ID);
    signer.markBurned(kp.publicKey.publicSeed);
    signer.markBurned(kp.publicKey.publicSeed);
    signer.markBurned(kp.publicKey.publicSeed);
    expect(signer.isBurned(kp.publicKey.publicSeed)).toBe(true);
  });

  it("burning one key does not affect another", () => {
    const signer = new QuipSigner(QUANTUM_SECRET);
    const a = signer.generateKeyPair(VAULT_ID);
    const b = signer.generateKeyPair(VAULT_ID);
    signer.markBurned(a.publicKey.publicSeed);
    expect(signer.isBurned(a.publicKey.publicSeed)).toBe(true);
    expect(signer.isBurned(b.publicKey.publicSeed)).toBe(false);
    // signing with b still works
    const sig = signer.sign(MESSAGE, VAULT_ID, b.publicKey.publicSeed);
    expect(sig.length).toBe(67);
  });

  it("clearBurnedForTesting resets the set", () => {
    const signer = new QuipSigner(QUANTUM_SECRET);
    const kp = signer.generateKeyPair(VAULT_ID);
    signer.markBurned(kp.publicKey.publicSeed);
    expect(signer.isBurned(kp.publicKey.publicSeed)).toBe(true);
    signer.clearBurnedForTesting();
    expect(signer.isBurned(kp.publicKey.publicSeed)).toBe(false);
    // and sign works again
    const sig = signer.sign(MESSAGE, VAULT_ID, kp.publicKey.publicSeed);
    expect(sig.length).toBe(67);
  });

  it("burned set is per-instance (separate signers track separately)", () => {
    const signerA = new QuipSigner(QUANTUM_SECRET);
    const signerB = new QuipSigner(QUANTUM_SECRET);
    const kp = signerA.generateKeyPair(VAULT_ID);
    signerA.markBurned(kp.publicKey.publicSeed);
    expect(signerA.isBurned(kp.publicKey.publicSeed)).toBe(true);
    expect(signerB.isBurned(kp.publicKey.publicSeed)).toBe(false);
  });
});
