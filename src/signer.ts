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

import { KeyAlreadyBurnedError } from "./errors.js";
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
/// forge. So this signer marks a key burned **inside `sign`**, right
/// after the WOTS+ signature is produced — not at broadcast time. The
/// guarantee: a successful `sign(...)` is the burn point, regardless of
/// what the caller does with the returned signature.
///
/// Why not "burn at broadcast" (the previous design): callers that
/// produce a sig and then abort (simulation reject, network error,
/// caller never submits) would leave the in-memory set unchanged. A
/// later call could pick the same key and sign a different message —
/// exactly the WOTS+ violation we need to prevent.
///
/// State is per-instance and not persisted across signer restarts; see
/// `SDK_README.md` for the persistence recommendation.
export class QuipSigner {
  private quantumSecret: Uint8Array;
  private wots: WOTSPlus;
  private burned: Set<Hex>;

  constructor(quantumSecret: Uint8Array) {
    this.wots = new WOTSPlus(keccak_256);
    this.quantumSecret = keccak_256(quantumSecret);
    this.burned = new Set();
  }

  /// Generate a fresh keypair under this `(quantumSecret, vaultId)` branch
  /// with a cryptographically random `publicSeed`.
  public generateKeyPair(vaultId: Hex): WinternitzKeyPair {
    const publicSeed = toHex(randomBytes(32));
    return this.recoverKeyPair(vaultId, publicSeed);
  }

  /// Rederive a previously-generated keypair from its `publicSeed`. The
  /// canonical lookup path: read a key's publicSeed from chain, pass it
  /// here to recover the private key for signing.
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
    return {
      privateKey: keypair.privateKey,
      publicKey: {
        publicSeed: toHex(keypair.publicKey.slice(0, 32)),
        publicKeyHash: toHex(keypair.publicKey.slice(32, 64)),
      },
    };
  }

  /// Sign `message` with the key derived from `(vaultId, publicSeed)`.
  /// Throws `KeyAlreadyBurnedError` if the key was already used. On
  /// success, marks the key burned **before returning** — once this
  /// method hands back a signature, the key is dead in this signer.
  ///
  /// The signature is returned as 67 `Hex` bytes32 elements, ready to
  /// drop straight into the codec's `WinternitzElements` shape:
  ///
  ///   const sig = signer.sign(digest, vaultId, currentKey.publicSeed);
  ///   const pqSig: WinternitzElements = { elements: sig };
  public sign(message: Hex, vaultId: Hex, publicSeed: Hex): Hex[] {
    if (this.burned.has(publicSeed)) {
      throw new KeyAlreadyBurnedError(publicSeed);
    }
    const key = this.recoverKeyPair(vaultId, publicSeed);
    const sig = this.wots.sign(
      key.privateKey,
      hexToBytes(key.publicKey.publicSeed),
      hexToBytes(message)
    );
    // Burn immediately after producing the signature. Any subsequent
    // sign() with this seed throws KeyAlreadyBurnedError. The wallet
    // client's post-broadcast `markBurned` is now an idempotent
    // safety-net (no-op when sign() already burned).
    this.burned.add(publicSeed);
    return sig.map((el) => toHex(el, { size: 32 }));
  }

  /// Mark a key burned. Idempotent; safe to call multiple times. The
  /// signer auto-burns inside `sign(...)`, so this is rarely needed
  /// directly — it remains exposed for callers that produce a signature
  /// outside this signer (e.g. via a future HSM-backed `PqSigner`) and
  /// need to record the burn in the in-memory set.
  public markBurned(publicSeed: Hex): void {
    this.burned.add(publicSeed);
  }

  /// Query whether `publicSeed` has been marked burned in this signer.
  public isBurned(publicSeed: Hex): boolean {
    return this.burned.has(publicSeed);
  }

  /// Test-only: clear the burned set. Production code should never call
  /// this — once a key is broadcast, it is gone. Exposed for unit tests
  /// that need a clean slate between cases.
  public clearBurnedForTesting(): void {
    this.burned.clear();
  }
}
