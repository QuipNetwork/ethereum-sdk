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
import { WOTSPlus } from "@quip.network/hashsigs";
import { keccak_256 } from "@noble/hashes/sha3";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { equalBytes } from "@noble/ciphers/utils";
import { type Hex, hexToBytes, toHex } from "viem";

import { type ConsumeKeyFn } from "./burnSet.js";
import { KeyDerivationSelfTestError } from "./errors.js";
import { type WinternitzAddress } from "./wotsCodec.js";

export interface WinternitzKeyPair {
  /// Secret material — kept as `Uint8Array` for wipe-ability. Never crosses
  /// into the viem/codec surface; consumers must not log or serialize this.
  privateKey: Uint8Array;
  /// Public component — Hex everywhere. Matches the codec/contract shape
  /// (`WinternitzAddress`) directly so the signer's outputs flow into
  /// `encodeInit` / `encodeExecute` / write APIs with no conversion.
  publicKey: WinternitzAddress;
}

/// Fixed sentinel digest signed locally as a post-derivation self-test on
/// every fresh WOTS+ keypair. Catches WOTS+ library bugs, memory corruption,
/// and silent derivation drift before the keypair is used for a real
/// signature.
///
/// Critical: the sentinel digest is constant and never used as a real signing
/// input. The sentinel signature is produced via the raw `WOTSPlus.sign`
/// path (bypassing `QuipSigner.sign` / `ConsumeKeyFn`), held only in a stack
/// local, and discarded immediately. It never crosses the SDK boundary, so
/// WOTS+ one-time-use is preserved — the key remains usable for one real
/// signature afterwards.
const KEY_SELFTEST_DIGEST: Uint8Array = keccak_256(
  new TextEncoder().encode("QUIP_WOTS_KEY_SELFTEST_v1")
);

/// In-memory WOTS+ signer keyed off a single `quantumSecret`. See
/// `SDK_README.md` for the operational contract (the "every broadcast burns
/// a key" invariant, concurrency model, and persistent-state
/// recommendations).
///
/// Mental model: `quantumSecret` is the user's seed-phrase analog —
/// analogous to a BIP39 mnemonic in classical wallets. From it, every
/// WOTS+ keypair the user ever uses is deterministically derived:
///
///   privateSeed = keccak256(quantumSecret) || vaultId
///   (privateKey, publicKey) = WOTSPlus.generateKeyPair(privateSeed, publicSeed)
///
/// Hierarchy:
///   - `quantumSecret`   : per-user master secret. Single backup target.
///     Stored as `Uint8Array` (wipe-able) and never leaked through the API.
///   - `vaultId`         : per-wallet branch (multiple vaults per user).
///     Passed as `Hex` on the public surface.
///   - `publicSeed`      : per-key salt; published on chain as part of
///                         the key's identity. Random at generation time.
///                         Returned as `Hex` for direct codec/viem use.
///
/// Given `(quantumSecret, vaultId, publicSeed)` the private key is
/// reproducible. The publicSeed is always readable from the wallet
/// (`keyAt`, `getDisasterRecoveryKey`, `getOwnershipKey`), so the user's
/// only off-chain backup obligation is the `quantumSecret`.
///
/// Burned-key tracking: WOTS+ is one-time-use. Producing a signature on
/// any message commits the key: once a sig exists, signing a different
/// message with the same key leaks secret material and lets an observer
/// forge. So `sign(...)` invokes the injected `ConsumeKeyFn` **before**
/// the WOTS+ signature is produced — the burn is committed first, and the
/// signature follows. If `consume` raises `KeyAlreadyBurnedError`, no
/// signature is produced. If the WOTS+ sign call itself throws (library
/// bug), the seed is already burned — conservative over-burn, the safe
/// failure mode.
///
/// The burn set is **not** owned by `QuipSigner`. Every signer is
/// constructed with a `ConsumeKeyFn` supplied by the caller. The SDK
/// ships `createInMemoryBurnSet()` as a process-local default; production
/// callers should back the function with durable storage so a restart
/// cannot resurrect a burned key. See `SDK_README.md`.
///
/// Post-derivation self-test: every `generateKeyPair` / `recoverKeyPair`
/// signs a fixed sentinel digest with the freshly derived material and
/// verifies the result against the public key. Catches derivation bugs
/// before the key is used for a real payload. The sentinel signature is
/// local, never returned, and never recorded against the burn set —
/// WOTS+ one-time-use is preserved.
export class QuipSigner {
  private quantumSecret: Uint8Array;
  private wots: WOTSPlus;
  private consume: ConsumeKeyFn;

  constructor(quantumSecret: Uint8Array, consume: ConsumeKeyFn) {
    this.wots = new WOTSPlus(keccak_256);
    this.quantumSecret = keccak_256(quantumSecret);
    this.consume = consume;
  }

  /// Generate a fresh keypair under this `(quantumSecret, vaultId)` branch
  /// with a cryptographically random `publicSeed`. Runs the self-test before
  /// returning.
  public generateKeyPair(vaultId: Hex): WinternitzKeyPair {
    const publicSeed = toHex(randomBytes(32));
    return this.recoverKeyPair(vaultId, publicSeed);
  }

  /// Rederive a previously-generated keypair from its `publicSeed`. The
  /// canonical lookup path: read a key's publicSeed from chain, pass it
  /// here to recover the private key for signing. Runs the self-test before
  /// returning.
  public recoverKeyPair(vaultId: Hex, publicSeed: Hex): WinternitzKeyPair {
    const publicSeedBytes = hexToBytes(publicSeed);
    const privateSeed = Uint8Array.from([
      ...this.quantumSecret,
      ...hexToBytes(vaultId),
    ]);
    const keypair = this.wots.generateKeyPair(privateSeed, publicSeedBytes);
    const returnedSeed = keypair.publicKey.slice(0, 32);
    if (!equalBytes(publicSeedBytes, returnedSeed)) {
      throw new Error("Invalid public seed returned: " + toHex(returnedSeed));
    }
    this._runSelfTest(keypair.privateKey, keypair.publicKey, publicSeedBytes, publicSeed);
    return {
      privateKey: keypair.privateKey,
      publicKey: {
        publicSeed: toHex(keypair.publicKey.slice(0, 32)),
        publicKeyHash: toHex(keypair.publicKey.slice(32, 64)),
      },
    };
  }

  /// Sign `message` with the key derived from `(vaultId, publicSeed)`.
  ///
  /// Burn semantics: `consume(publicSeed)` runs **before** the WOTS+
  /// signature is produced. If it throws (`KeyAlreadyBurnedError` from the
  /// injected burn set), no signature is generated. On a successful
  /// `consume`, the WOTS+ sign call runs; if it raises, the seed is
  /// already burned — the safe failure mode.
  ///
  /// The method is `async` so production `ConsumeKeyFn` implementations
  /// backed by Redis / Postgres / KMS can return a Promise; the await runs
  /// inside this method, so a sync `consume` works transparently too. The
  /// WOTS+ signing itself is synchronous.
  ///
  /// The signature is returned as 67 `Hex` bytes32 elements, ready to
  /// drop straight into the codec's `WinternitzElements` shape:
  ///
  ///   const sig = await signer.sign(digest, vaultId, currentKey.publicSeed);
  ///   const pqSig: WinternitzElements = { elements: sig };
  public async sign(message: Hex, vaultId: Hex, publicSeed: Hex): Promise<Hex[]> {
    await this.consume(publicSeed);
    const key = this.recoverKeyPair(vaultId, publicSeed);
    const sig = this.wots.sign(
      key.privateKey,
      hexToBytes(key.publicKey.publicSeed),
      hexToBytes(message)
    );
    return sig.map((el) => toHex(el, { size: 32 }));
  }

  /// Sign the sentinel digest with the freshly derived keypair, then verify
  /// against the public key. Throws `KeyDerivationSelfTestError` if the
  /// round-trip fails — derivation produced material that does not satisfy
  /// the WOTS+ contract.
  ///
  /// Bypasses `this.consume`: the sentinel signature is local-only,
  /// short-lived, and intentionally not recorded against the burn set. The
  /// key remains usable for exactly one real signature afterwards (WOTS+
  /// one-time-use preserved — the sentinel sig is never observable outside
  /// this stack frame).
  private _runSelfTest(
    privateKey: Uint8Array,
    publicKey: Uint8Array,
    publicSeedBytes: Uint8Array,
    publicSeed: Hex
  ): void {
    const sig = this.wots.sign(privateKey, publicSeedBytes, KEY_SELFTEST_DIGEST);
    const ok = this.wots.verify(publicKey, KEY_SELFTEST_DIGEST, sig);
    if (!ok) {
      throw new KeyDerivationSelfTestError(publicSeed);
    }
  }
}
