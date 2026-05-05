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

export class QuipSigner {
  // FIXME: in an ideal world these are kept in a secure wallet somewhere and this is
  // merely an interface. For now we are keeping them in memory.
  private quantumSecret: Uint8Array;
  private wots: WOTSPlus;

  constructor(quantumSecret: Uint8Array) {
    this.wots = new WOTSPlus(keccak_256);
    this.quantumSecret = keccak_256(quantumSecret);
  }

  // generateKeyPair in the domain of a specific vault using the base quantum
  // secret.
  public generateKeyPair(vaultId: Uint8Array): WinternitzKeyPair {
    const publicSeed = randomBytes(32);
    return this.recoverKeyPair(vaultId, publicSeed);
  }

  // recoverKeyPair given a pre-existing public seed, and vault id
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
