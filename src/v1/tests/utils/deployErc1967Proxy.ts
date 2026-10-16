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

/// Family-agnostic test-fixture helper shared by the SHRINCS fixture and the
/// deprecated WOTS+ fixture. Extracted from the WOTS+ `anvilFixture.ts` when
/// that fixture moved to `src/deprecated/v1/tests/` — live fixtures must not
/// import from `deprecated/`.
import {
  type Address,
  type Chain,
  type PrivateKeyAccount,
  type PublicClient,
  type WalletClient,
  concat,
} from "viem";
import { foundry } from "viem/chains";

/// Deploy a Solady minimal ERC-1967 proxy pointing at `impl`. Initcode
/// mirrors `WalletFactory._deployProxy`'s emission so the on-chain layout
/// matches what the factory produces.
export async function deployErc1967Proxy(
  walletClient: WalletClient,
  publicClient: PublicClient,
  account: PrivateKeyAccount,
  impl: Address,
  chain: Chain = foundry
): Promise<Address> {
  const initcode = concat([
    "0x603d3d8160223d3973",
    impl,
    "0x6009",
    "0x5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076",
    "0xcc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3",
  ]);
  const hash = await walletClient.sendTransaction({
    chain,
    data: initcode,
    account,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  return receipt.contractAddress!;
}
