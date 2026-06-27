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
import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  createPublicClient,
  createWalletClient,
  http,
} from "viem";
import { createAnvil } from "@viem/anvil";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { quipFactoryAbi } from "../abi/QuipFactory.js";
import {
  decodeContractError,
  withDecodedError,
} from "../internal/decodeError.js";
import {
  FeeExceedsMaxError,
  InsufficientBalanceError,
  ZeroMaxFeeError,
  QuipError,
} from "../errors.js";

// ─── Forge artifact ─────────────────────────────────────────────────
const factoryArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/QuipFactory.sol/QuipFactory.json"),
    "utf8"
  )
);
const factoryBytecode = factoryArtifact.bytecode.object as Hex;

// Anvil's first prefunded account.
const ANVIL_PRIV_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(ANVIL_PRIV_KEY);

// ─── Anvil lifecycle ────────────────────────────────────────────────
// Distinct port from wotsCodec.test.ts (default 8545) so jest's parallel
// runner can boot both Anvil instances simultaneously.
const anvil = createAnvil({ port: 8547 });
let publicClient: PublicClient;
let walletClient: WalletClient;
let factoryAddress: Address;

const MAX_FEE = 10n ** 16n; // 0.01 ETH — well under any practical bound

beforeAll(async () => {
  await anvil.start();
  const transport = http(`http://127.0.0.1:${anvil.port}`);
  publicClient = createPublicClient({ chain: foundry, transport });
  walletClient = createWalletClient({ chain: foundry, transport, account });

  const hash = await walletClient.deployContract({
    abi: quipFactoryAbi,
    bytecode: factoryBytecode,
    args: [account.address, MAX_FEE],
    account,
    chain: foundry,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  factoryAddress = receipt.contractAddress!;
}, 30_000);

afterAll(async () => {
  await anvil.stop().catch(() => {});
}, 10_000);

// ─── Tests ──────────────────────────────────────────────────────────

describe("Anvil — QuipFactory error decoding", () => {
  test("setExecuteFee above MAX_FEE → FeeExceedsMaxError with parsed args", async () => {
    let caught: unknown = null;
    try {
      await withDecodedError(
        walletClient.writeContract({
          chain: foundry,
          address: factoryAddress,
          abi: quipFactoryAbi,
          functionName: "setExecuteFee",
          args: [MAX_FEE + 1n],
          account,
        })
      );
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(FeeExceedsMaxError);
    const err = caught as FeeExceedsMaxError;
    expect(err.fee).toBe(MAX_FEE + 1n);
    expect(err.maxFee).toBe(MAX_FEE);
    expect(err.cause).toBeDefined();
  });

  test("withdraw above factory balance → InsufficientBalanceError with parsed args", async () => {
    // Factory has zero balance at this point.
    let caught: unknown = null;
    try {
      await withDecodedError(
        walletClient.writeContract({
          chain: foundry,
          address: factoryAddress,
          abi: quipFactoryAbi,
          functionName: "withdraw",
          args: [1000n],
          account,
        })
      );
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(InsufficientBalanceError);
    const err = caught as InsufficientBalanceError;
    expect(err.requested).toBe(1000n);
    expect(err.available).toBe(0n);
  });

  test("constructor(maxFee_=0) → ZeroMaxFeeError (deploy-revert path)", async () => {
    let caught: unknown = null;
    try {
      await withDecodedError(
        walletClient.deployContract({
          abi: quipFactoryAbi,
          bytecode: factoryBytecode,
          args: [account.address, 0n],
          account,
          chain: foundry,
        })
      );
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ZeroMaxFeeError);
  });

  test("decodeContractError handles a real revert without withDecodedError wrapper", async () => {
    // Demonstrate the lower-level API: catch the raw viem error, then decode.
    let raw: unknown = null;
    try {
      await walletClient.writeContract({
        chain: foundry,
        address: factoryAddress,
        abi: quipFactoryAbi,
        functionName: "setCreationFee",
        args: [MAX_FEE + 100n],
        account,
      });
    } catch (e) {
      raw = e;
    }
    expect(raw).not.toBeNull();
    const decoded = decodeContractError(raw) as QuipError;
    expect(decoded).toBeInstanceOf(FeeExceedsMaxError);
    expect((decoded as FeeExceedsMaxError).fee).toBe(MAX_FEE + 100n);
  });
});
