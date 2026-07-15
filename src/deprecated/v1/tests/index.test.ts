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
import { toHex } from "viem";
import {
  QuipSigner as BarrelQuipSigner,
  WOTSPlusImplementationClient as BarrelWOTSPlusImplementationClient,
  QuipClient as BarrelQuipClient,
  KeyType as BarrelKeyType,
  wotsPlusImplementationAbi,
  walletFactoryAbi,
  quipPaymasterAbi,
  deployerAbi,
} from "../index.js";

import { QuipSigner } from "../signer.js";
import { createInMemoryBurnSet } from "../burnSet.js";
import { WOTSPlusImplementationClient, KeyType } from "../walletClient.js";
import { QuipClient } from "../factoryClient.js";

describe("Phase 0 module split", () => {
  test("barrel exports are identical to module exports", () => {
    expect(BarrelQuipSigner).toBe(QuipSigner);
    expect(BarrelWOTSPlusImplementationClient).toBe(WOTSPlusImplementationClient);
    expect(BarrelQuipClient).toBe(QuipClient);
    expect(BarrelKeyType).toBe(KeyType);
  });

  test("KeyType enum values mirror IWOTSPlusImplementation.KeyType", () => {
    expect(KeyType.Transaction).toBe(0);
    expect(KeyType.Recovery).toBe(1);
    expect(KeyType.Verification).toBe(2);
  });

  test("QuipSigner instantiates and produces a deterministic key pair from a seed", () => {
    const secret = new Uint8Array(32).fill(1);
    const vaultId = toHex(new Uint8Array(32).fill(2));
    const publicSeed = toHex(new Uint8Array(32).fill(3));

    const signer = new QuipSigner(secret, createInMemoryBurnSet().consume);
    const a = signer.recoverKeyPair(vaultId, publicSeed);
    const b = signer.recoverKeyPair(vaultId, publicSeed);

    expect(a.publicKey.publicSeed).toEqual(b.publicKey.publicSeed);
    expect(a.publicKey.publicKeyHash).toEqual(b.publicKey.publicKeyHash);
    expect(a.privateKey).toEqual(b.privateKey);
  });

  test("ABIs are exported from the barrel", () => {
    expect(Array.isArray(wotsPlusImplementationAbi)).toBe(true);
    expect(Array.isArray(walletFactoryAbi)).toBe(true);
    expect(Array.isArray(quipPaymasterAbi)).toBe(true);
    expect(Array.isArray(deployerAbi)).toBe(true);
  });
});
