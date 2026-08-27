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

import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha2";

import { ShrincsHdDerivationError } from "./errors.js";

/// QUIP HD derivation v1 — hardened-only, SLIP-0010-style HMAC-SHA512 chains.
/// Hash-based keys have no parent-to-child public-key relation, so every
/// level is hardened and there is no xpub concept.
///
/// Path: m / QUIP_HD_PURPOSE' / algorithm' / network' / account' / index'

/// Purpose level: 0x514E = ASCII "QN" big-endian, the QUIP HD scheme marker.
export const QUIP_HD_PURPOSE = 0x514e;

/// Reserved experimental algorithm identifier. The SHRINCS profile is
/// pre-standard; registered identifiers will be assigned below 0x7F000000.
export const ALGORITHM_EXPERIMENTAL = 0x7fffffff;

/// Network identifier: the QUIP network chain ID, 20049 (0x4E51, ASCII "QN"
/// little-endian). A fixed constant — it does not follow the deployment
/// chain, so one mnemonic yields the same keys on every EVM chain.
export const NETWORK_QUIP = 20049;

/// BIP-32 hardened index offset (2^31).
export const HARDENED_OFFSET = 0x80000000;

const MASTER_HMAC_KEY = new TextEncoder().encode("QUIP seed");
const MIN_SEED_BYTES = 16;

export interface HdNode {
  readonly key: Uint8Array; // 32 bytes — the child secret
  readonly chainCode: Uint8Array; // 32 bytes
}

function splitI(i: Uint8Array): HdNode {
  return { key: i.slice(0, 32), chainCode: i.slice(32, 64) };
}

/// Master node: I = HMAC-SHA512(key = "QUIP seed", data = seed).
export function masterNodeFromSeed(seed: Uint8Array): HdNode {
  if (seed.length < MIN_SEED_BYTES) {
    throw new ShrincsHdDerivationError(
      `master seed must be at least ${MIN_SEED_BYTES} bytes, got ${seed.length}`
    );
  }
  return splitI(hmac(sha512, MASTER_HMAC_KEY, seed));
}

/// Hardened CKD: I = HMAC-SHA512(chainCode, 0x00 ‖ key ‖ ser32BE(index + 2^31)).
export function deriveHardenedChild(node: HdNode, index: number): HdNode {
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
    throw new ShrincsHdDerivationError(
      `derivation index must be an integer in [0, 2^31), got ${index}`
    );
  }
  const data = new Uint8Array(1 + 32 + 4);
  data[0] = 0x00;
  data.set(node.key, 1);
  new DataView(data.buffer).setUint32(33, index + HARDENED_OFFSET, false);
  return splitI(hmac(sha512, node.chainCode, data));
}
