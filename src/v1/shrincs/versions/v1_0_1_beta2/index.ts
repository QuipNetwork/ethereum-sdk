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
// The FROZEN V1.0.1-beta.2 ShrincsWallet generation: the implementation existing
// wallets on Base mainnet + testnets still run. The SDK keeps operating and
// UPGRADING these wallets, so this descriptor and its ABI snapshot are a
// read-only record of deployed reality — never regenerated from the working tree.

import type { Abi, Address } from "viem";

import { SHRINCS_WALLET_BETA2_IMPLEMENTATION } from "../../addresses.js";
import type { WalletVersionDescriptor } from "../types.js";
import { shrincsWalletBeta2Abi } from "./abi.js";

export const V1_0_1_BETA2_IMPLEMENTATIONS: readonly Address[] = [
  SHRINCS_WALLET_BETA2_IMPLEMENTATION,
];

export const v1_0_1_beta2: WalletVersionDescriptor = {
  id: "v1.0.1-beta.2",
  label: "V1.0.1-beta.2",
  abi: shrincsWalletBeta2Abi as unknown as Abi,
  implementations: V1_0_1_BETA2_IMPLEMENTATIONS,
  quirks: {
    erc1271CommitmentGetter: "getErc1271Commitment",
    erc1271KeyArgument: "bytes32Commitment",
    hasStatefulLeafBitmapWord: false,
    enforcesSpentTreeFreshnessOnMigrate: false,
  },
};
