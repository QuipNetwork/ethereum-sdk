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
// The FROZEN V1.0.1-beta.3 ShrincsWallet generation (audit fixes: four-tree
// ERC-1271 isolation, two-party handover). It runs against the pre-0.4.0
// hashsigs verifier, so its stateless signatures are ABI structs. Wallets on
// this generation stay operable and upgradable; this descriptor and its ABI
// snapshot are a read-only record of deployed reality.

import type { Abi, Address } from "viem";

import { SHRINCS_WALLET_BETA3_IMPLEMENTATION } from "../../addresses.js";
import type { WalletVersionDescriptor } from "../types.js";
import { shrincsWalletBeta3Abi } from "./abi.js";

export const V1_0_1_BETA3_IMPLEMENTATIONS: readonly Address[] = [
  SHRINCS_WALLET_BETA3_IMPLEMENTATION,
];

export const v1_0_1_beta3: WalletVersionDescriptor = {
  id: "v1.0.1-beta.3",
  label: "V1.0.1-beta.3",
  abi: shrincsWalletBeta3Abi as unknown as Abi,
  implementations: V1_0_1_BETA3_IMPLEMENTATIONS,
  quirks: {
    erc1271CommitmentGetter: "getErc1271PublicKeyCommitment",
    erc1271KeyArgument: "publicKeyBundle",
    hasStatefulLeafBitmapWord: true,
    enforcesSpentTreeFreshnessOnMigrate: true,
    handoverAcceptance: "hybrid",
    statelessSignatureEncoding: "abiStruct",
  },
};
