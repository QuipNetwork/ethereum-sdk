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

export interface WinternitzKeyPair {
  privateKey: Uint8Array;
  publicKey: WinternitzPublicKey;
}

export interface WinternitzPublicKey {
  publicSeed: Uint8Array;
  publicKeyHash: Uint8Array;
}

/// In-memory WOTS+ signer keyed off a single `quantumSecret`.
///
/// Mental model: `quantumSecret` is the user's seed-phrase analog —
/// analogous to a BIP39 mnemonic in classical wallets. From it, every
/// WOTS+ keypair the user ever uses is deterministically derived:
///
///   privateSeed = quantumSecret || vaultId
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
/// Lifetime: the secret lives in memory for the lifetime of this
/// `QuipSigner` instance — session-scoped, like MetaMask's seed in a
/// decrypted vault. Encryption at rest, passphrase unlock, lock
/// timeouts, and wiping on logout are the embedding application's
/// responsibility; the SDK only consumes a raw `Uint8Array`.
///
/// Future direction: a `PqSigner` interface would let HSM /
/// hardware-wallet backends supply the same shape without exposing
/// the secret to JS at all. Out of scope for this phase.
export class QuipSigner {
  // FIXME: in an ideal world these are kept in a secure wallet somewhere and this is
  // merely an interface. For now we are keeping them in memory.
  private quantumSecret: Uint8Array;
  private wots: WOTSPlus;

  constructor(quantumSecret: Uint8Array) {
    this.wots = new WOTSPlus(keccak_256);
    this.quantumSecret = keccak_256(quantumSecret);
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

  public sign(
    message: Uint8Array,
    vaultId: Uint8Array,
    publicSeed: Uint8Array
  ): Uint8Array[] {
    const key = this.recoverKeyPair(vaultId, publicSeed);
    return this.wots.sign(key.privateKey, key.publicKey.publicSeed, message);
  }
}
