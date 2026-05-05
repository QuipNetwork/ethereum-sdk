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
import { type Hex, toHex } from "viem";

import type { WinternitzPublicKey } from "../signer.js";

/// The ABI expects bytes32[67] for a WOTS+ signature; this fixed-length tuple
/// is what viem requires for typed argument passing.
export type Bytes32Tuple67 = readonly [
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex,
];

export function pubkeyToHex(pk: WinternitzPublicKey): {
  publicSeed: Hex;
  publicKeyHash: Hex;
} {
  return {
    publicSeed: toHex(pk.publicSeed),
    publicKeyHash: toHex(pk.publicKeyHash),
  };
}

export function sigToHex(sig: Uint8Array[]): Bytes32Tuple67 {
  return sig.map((el) => toHex(el, { size: 32 })) as unknown as Bytes32Tuple67;
}
