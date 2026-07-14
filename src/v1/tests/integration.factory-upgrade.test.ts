// Copyright (C) 2026 quip.network
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
import { describe, test, expect, beforeAll, afterAll } from "@jest/globals";
import { foundry } from "viem/chains";

import { quipFactoryAbi } from "../abi/QuipFactory.js";
import { computeVaultAddress } from "../addresses.js";
import { parseQuipCreated } from "../events.js";
import {
  ANVIL_PORTS,
  type AnvilStack,
  createFreshWallet,
  loadForgeArtifacts,
  setupAnvilStack,
  stopAnvilStack,
} from "./utils/anvilFixture.js";

let stack: AnvilStack;

beforeAll(async () => {
  stack = await setupAnvilStack({
    port: ANVIL_PORTS.factoryUpgrade,
    deployEntryPoint: false, // pure factory/registry paths, no 4337
  });
}, 60_000);

afterAll(async () => {
  await stopAnvilStack(stack);
}, 10_000);

/// The factory is UUPS behind an ERC-1967 proxy: its logic is replaceable but
/// the PROXY address is the permanent identity wallets bake in. This suite
/// upgrades the live factory mid-flight and asserts nothing an SDK consumer
/// relies on moves: the registry, counterfactual CREATE3 wallet addresses,
/// event parsing, and pre-upgrade wallets' ability to keep executing.
describe("Factory UUPS upgrade continuity", () => {
  test("upgrade preserves registry, addresses, events, and live wallets", async () => {
    // ── Pre-upgrade state: one wallet + its registry entries.
    const pre = await createFreshWallet(stack, 0xd0);
    const preOwner = await stack.publicClient.readContract({
      address: stack.factoryAddress,
      abi: quipFactoryAbi,
      functionName: "walletOwner",
      args: [pre.walletAddress],
    });
    expect(preOwner.toLowerCase()).toBe(stack.account.address.toLowerCase());

    // ── Upgrade: deploy a fresh impl (same code, DIFFERENT per-impl
    // MAX_FEE so the swap is observable) and upgradeToAndCall as owner.
    const { factoryBytecode } = loadForgeArtifacts();
    const newMaxFee = 2n * 10n ** 17n; // 0.2 ether vs the default 0.1
    const implHash = await stack.walletClient.deployContract({
      abi: quipFactoryAbi,
      bytecode: factoryBytecode,
      args: [newMaxFee],
      account: stack.account,
      chain: foundry,
    });
    const implReceipt = await stack.publicClient.waitForTransactionReceipt({
      hash: implHash,
    });
    const newImpl = implReceipt.contractAddress!;
    const upgradeHash = await stack.walletClient.writeContract({
      address: stack.factoryAddress,
      abi: quipFactoryAbi,
      functionName: "upgradeToAndCall",
      args: [newImpl, "0x"],
      account: stack.account,
      chain: foundry,
    });
    await stack.publicClient.waitForTransactionReceipt({ hash: upgradeHash });

    // The per-implementation immutable moved with the impl…
    const maxFee = await stack.publicClient.readContract({
      address: stack.factoryAddress,
      abi: quipFactoryAbi,
      functionName: "MAX_FEE",
    });
    expect(maxFee).toBe(newMaxFee);

    // …while the ERC-7201 registry state read back unchanged.
    const ownerAfter = await stack.publicClient.readContract({
      address: stack.factoryAddress,
      abi: quipFactoryAbi,
      functionName: "walletOwner",
      args: [pre.walletAddress],
    });
    expect(ownerAfter.toLowerCase()).toBe(
      stack.account.address.toLowerCase()
    );
    const registered = await stack.publicClient.readContract({
      address: stack.factoryAddress,
      abi: quipFactoryAbi,
      functionName: "wallets",
      args: [pre.vaultId],
    });
    expect(registered.toLowerCase()).toBe(pre.walletAddress.toLowerCase());

    // ── Counterfactual stability: a post-upgrade deployment lands at the
    // address predicted from the PROXY (CREATE3 ignores the impl swap).
    const post = await createFreshWallet(stack, 0xd1);
    expect(post.walletAddress.toLowerCase()).toBe(
      computeVaultAddress(stack.factoryAddress, post.vaultId).toLowerCase()
    );

    // The event parser keeps working and reports the NEW implementation…
    const events = parseQuipCreated(post.creationReceipt);
    expect(events).toHaveLength(1);
    // (wallet impl, not factory impl — the field identifies the WALLET
    // implementation the proxy was deployed with)
    expect(events[0].implementation.toLowerCase()).toBe(
      stack.walletImplAddress.toLowerCase()
    );

    // ── The PRE-upgrade wallet still executes through its baked-in factory
    // pointer (fee read + key rotation land against the upgraded logic).
    const recipient = "0x000000000000000000000000000000000000dEaD" as const;
    const receipt = await pre.client.executeWithPayload(recipient, 100n, "0x");
    expect(receipt.status).toBe("success");
  }, 120_000);
});
