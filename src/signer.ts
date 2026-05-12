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
import { type Hex, toHex } from "viem";

import { KeyAlreadyBurnedError } from "./errors.js";

export interface WinternitzKeyPair {
  privateKey: Uint8Array;
  publicKey: WinternitzPublicKey;
}

export interface WinternitzPublicKey {
  publicSeed: Uint8Array;
  publicKeyHash: Uint8Array;
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
///   - `vaultId`         : per-wallet branch (multiple vaults per user).
///   - `publicSeed`      : per-key salt; published on chain as part of
///                         the key's identity. Random at generation time.
///
/// Given `(quantumSecret, vaultId, publicSeed)` the private key is
/// reproducible. The publicSeed is always readable from the wallet
/// (`keyAt`, `getDisasterRecoveryKey`, `getOwnershipKey`), so the user's
/// only off-chain backup obligation is the `quantumSecret`.
///
/// Burned-key tracking: WOTS+ is one-time-use. Once a signature has been
/// broadcast, the key is publicly compromised — reuse leaks secret
/// material and lets an observer forge sigs on different messages. This
/// signer maintains an in-memory set of burned publicSeeds; `sign` refuses
/// to operate on a burned key (`KeyAlreadyBurnedError`). The wallet client
/// calls `markBurned` immediately after `writeContract` returns the tx
/// hash, so the burn is recorded even if `waitForTransactionReceipt`
/// fails. State is per-instance and not persisted; see `SDK_README.md` for
/// the persistence recommendation.
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
  public generateKeyPair(vaultId: Uint8Array): WinternitzKeyPair {
    const publicSeed = randomBytes(32);
    return this.recoverKeyPair(vaultId, publicSeed);
  }

  /// Rederive a previously-generated keypair from its `publicSeed`. The
  /// canonical lookup path: read a key's publicSeed from chain, pass it
  /// here to recover the private key for signing.
  public recoverKeyPair(
    vaultId: Uint8Array,
    publicSeed: Uint8Array
  ): WinternitzKeyPair {
    const privateSeed = Uint8Array.from([...this.quantumSecret, ...vaultId]);
    const keypair = this.wots.generateKeyPair(privateSeed, publicSeed);
    const returnedSeed = keypair.publicKey.slice(0, 32);
    if (!equalBytes(publicSeed, returnedSeed)) {
      throw new Error("Invalid public seed returned: " + returnedSeed);
    }
    return {
      privateKey: keypair.privateKey,
      publicKey: {
        publicSeed: keypair.publicKey.slice(0, 32),
        publicKeyHash: keypair.publicKey.slice(32, 64),
      },
    };
  }

  /// Sign `message` with the key derived from `(vaultId, publicSeed)`. Throws
  /// `KeyAlreadyBurnedError` if this signer has already marked the key
  /// burned via `markBurned`.
  public sign(
    message: Uint8Array,
    vaultId: Uint8Array,
    publicSeed: Uint8Array
  ): Uint8Array[] {
    const seedHex = toHex(publicSeed);
    if (this.burned.has(seedHex)) {
      throw new KeyAlreadyBurnedError(seedHex);
    }
    const key = this.recoverKeyPair(vaultId, publicSeed);
    return this.wots.sign(key.privateKey, key.publicKey.publicSeed, message);
  }

  /// Mark a key burned. Called by `QuipWalletClient` immediately after
  /// `writeContract` returns a tx hash — at that point the WOTS+ signature
  /// is in the public mempool and the key is compromised regardless of
  /// whether the tx eventually mines. Idempotent.
  public markBurned(publicSeed: Uint8Array | Hex): void {
    const seedHex =
      typeof publicSeed === "string" ? publicSeed : toHex(publicSeed);
    this.burned.add(seedHex);
  }

  /// Query whether `publicSeed` has been marked burned in this signer.
  public isBurned(publicSeed: Uint8Array | Hex): boolean {
    const seedHex =
      typeof publicSeed === "string" ? publicSeed : toHex(publicSeed);
    return this.burned.has(seedHex);
  }

  /// Test-only: clear the burned set. Production code should never call
  /// this — once a key is broadcast, it is gone. Exposed for unit tests
  /// that need a clean slate between cases.
  public clearBurnedForTesting(): void {
    this.burned.clear();
  }
}
