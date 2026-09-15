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
//
// Wallet version resolution: a beta.2 wallet must be recognized from its
// installed implementation and mapped to the FROZEN beta.2 surface; any other
// implementation falls through to the `latest` (working-tree) surface, and the
// strict resolver rejects an unrecognized one.
import { describe, it, expect } from "@jest/globals";
import { getAddress, type Address } from "viem";

import { SHRINCS_WALLET_BETA2_IMPLEMENTATION } from "../addresses.js";
import { UnknownWalletVersionError } from "../errors.js";
import {
  KNOWN_WALLET_VERSIONS,
  LATEST_WALLET_VERSION,
  resolveWalletVersion,
  resolveWalletVersionStrict,
  shrincsWalletBeta2Abi,
  v1_0_1_beta2,
} from "../versions/index.js";

const RANDOM_IMPL = "0x00000000000000000000000000000000DeaDBeef" as Address;

describe("wallet version resolution", () => {
  it("recognizes the beta.2 implementation as the frozen beta.2 generation", () => {
    const v = resolveWalletVersion(SHRINCS_WALLET_BETA2_IMPLEMENTATION);
    expect(v.id).toBe("v1.0.1-beta.2");
    expect(v).toBe(v1_0_1_beta2);
    expect(v.abi).toBe(shrincsWalletBeta2Abi);
  });

  it("recognizes beta.2 regardless of address checksum casing", () => {
    const lower = SHRINCS_WALLET_BETA2_IMPLEMENTATION.toLowerCase() as Address;
    expect(resolveWalletVersion(lower).id).toBe("v1.0.1-beta.2");
  });

  it("falls through to latest for an unrecognized implementation", () => {
    expect(resolveWalletVersion(RANDOM_IMPL)).toBe(LATEST_WALLET_VERSION);
  });

  it("strict resolver rejects an unrecognized implementation", () => {
    expect(() => resolveWalletVersionStrict(RANDOM_IMPL)).toThrow(
      UnknownWalletVersionError
    );
  });

  it("strict resolver still recognizes beta.2", () => {
    expect(resolveWalletVersionStrict(SHRINCS_WALLET_BETA2_IMPLEMENTATION).id).toBe(
      "v1.0.1-beta.2"
    );
  });

  it("beta.2 quirks describe the deployed surface", () => {
    expect(v1_0_1_beta2.quirks).toEqual({
      erc1271CommitmentGetter: "getErc1271Commitment",
      erc1271KeyArgument: "bytes32Commitment",
      hasStatefulLeafBitmapWord: false,
      enforcesSpentTreeFreshnessOnMigrate: false,
      handoverAcceptance: "none",
    });
  });

  it("beta.2 ABI is the frozen deployed surface, not the current one", () => {
    const fnNames = new Set(
      (shrincsWalletBeta2Abi as ReadonlyArray<{ type: string; name?: string }>)
        .filter((e) => e.type === "function")
        .map((e) => e.name)
    );
    // Renamed getter + audit-fix additions distinguish the generations.
    expect(fnNames.has("getErc1271Commitment")).toBe(true);
    expect(fnNames.has("getErc1271PublicKeyCommitment")).toBe(false);
    expect(fnNames.has("statefulLeafBitmapWord")).toBe(false);
  });

  it("only frozen generations are address-resolvable; latest is the fallback", () => {
    expect(KNOWN_WALLET_VERSIONS.every((v) => v.id !== "latest")).toBe(true);
    expect(LATEST_WALLET_VERSION.implementations).toHaveLength(0);
    // The beta.2 address is byte-identical to today's live latest impl, but it
    // is registered under the frozen generation so it resolves there.
    expect(getAddress(v1_0_1_beta2.implementations[0])).toBe(
      getAddress(SHRINCS_WALLET_BETA2_IMPLEMENTATION)
    );
  });
});
