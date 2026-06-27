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
// Dual-signature contract test for the direct-path `execute(bytes)`.
// Every wallet write on this path requires TWO signatures:
//
//   1. ECDSA (outer) — the EOA's tx signature. The wallet's `onlyOwner`
//      modifier gates this: `msg.sender == owner` or revert with
//      `Unauthorized()`. The signature itself is at the transport layer
//      (viem's `walletClient.writeContract` signs the tx via the bound
//      account); the wallet doesn't see the signature bytes, only the
//      derived `msg.sender`.
//
//   2. WOTS+ (inner) — the post-quantum signature embedded in the
//      `bytes` payload. The wallet's `_verifyAndRotate` verifies the
//      WOTS+ sig against the current key, then rotates to next.
//      Failure reverts with `InvalidSignature()`.
//
// Both must succeed for the call to land. This test exercises:
//   - Happy path: owner ECDSA + valid WOTS+ → success
//   - Wrong ECDSA: non-owner EOA + valid WOTS+ → reverts (Unauthorized)
//   - Wrong WOTS+: owner ECDSA + tampered WOTS+ sig → reverts (InvalidSignature)
//
// This is the security property check for the direct path. The 4337
// path uses different gating (`onlyEntryPoint` instead of `onlyOwner`)
// and is covered by `integration.erc4337-*.test.ts`.
import { describe, test, expect, beforeAll, afterAll } from "@jest/globals";
import {
  type Hex,
  type WalletClient,
  createWalletClient,
  http,
  toHex,
  zeroAddress,
} from "viem";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

import { quipWalletAbi } from "./abi/QuipWallet.js";
import { QuipWalletClient } from "./walletClient.js";
import {
  InvalidSignatureError,
  UnknownContractError,
} from "./errors.js";
import { withDecodedError } from "./internal/decodeError.js";
import {
  encodeExecute,
  executeDigest,
  opdataHash,
  type WinternitzElements,
} from "./wotsCodec.js";
import {
  ANVIL_PORTS,
  type AnvilStack,
  createFreshWallet,
  setupAnvilStack,
  stopAnvilStack,
} from "./test-utils/anvilFixture.js";

// Anvil's prefunded dev account #1, used as the "stranger" (non-owner) to
// test the ECDSA gate. The owner comes from the default fixture
// (anvil's #0).
const STRANGER_PRIV =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const stranger = privateKeyToAccount(STRANGER_PRIV);

let stack: AnvilStack;
let strangerWallet: WalletClient;

beforeAll(async () => {
  stack = await setupAnvilStack({
    port: ANVIL_PORTS.dualSig,
    deployEntryPoint: false,
  });
  strangerWallet = createWalletClient({
    chain: foundry,
    transport: http(`http://127.0.0.1:${stack.anvil.port}`),
    account: stranger,
  });
}, 60_000);

afterAll(async () => {
  await stopAnvilStack(stack);
}, 10_000);

describe("Dual-signature contract on execute(bytes)", () => {
  test("happy path: owner ECDSA + valid WOTS+ succeeds", async () => {
    const { client, walletAddress } = await createFreshWallet(stack, 0xd0);

    // The SDK's `executeWithPayload` does both halves transparently:
    //   - viem's `walletClient.writeContract` signs the outer tx with the
    //     bound `owner` account (ECDSA at the transport layer).
    //   - The bytes payload contains the WOTS+ sig the SDK produced via
    //     `QuipSigner.sign`.
    // Either half failing would revert; success here proves both worked.
    const receipt = await client.executeWithPayload(zeroAddress, 0n, "0x");
    expect(receipt.status).toBe("success");
    expect(receipt.to?.toLowerCase()).toBe(walletAddress.toLowerCase());
  }, 30_000);

  test("wrong ECDSA: non-owner EOA + valid WOTS+ reverts via onlyOwner", async () => {
    const { signer, vaultId, walletAddress } = await createFreshWallet(
      stack,
      0xd1
    );

    // Construct a QuipWalletClient bound to `stranger` (non-owner EOA)
    // but using the real signer/vaultId so the WOTS+ half is valid. The
    // EOA mismatch is what should trip the gate — proving the ECDSA
    // outer is independently enforced.
    const strangerClient = new QuipWalletClient(
      signer,
      vaultId,
      walletAddress,
      stack.publicClient,
      strangerWallet,
      stranger.address,
      foundry.id
    );

    // Gas estimation catches the revert. The wallet uses Solady's
    // `Ownable` which reverts with `Unauthorized()` — not in our typed
    // error registry, so it surfaces as `UnknownContractError` with the
    // error name preserved.
    let caught: unknown = null;
    try {
      await strangerClient.executeWithPayload(zeroAddress, 0n, "0x");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(UnknownContractError);
    const unknown = caught as UnknownContractError;
    expect(unknown.errorName).toBe("Unauthorized");
  }, 30_000);

  test("wrong WOTS+: owner ECDSA + tampered WOTS+ sig reverts via _verifyAndRotate", async () => {
    const { signer, vaultId, client, walletAddress } = await createFreshWallet(
      stack,
      0xd2
    );

    // Build the `execute(bytes)` payload by hand so we can tamper one of
    // the WOTS+ sig elements after signing. The SDK normally hides this
    // — we replicate its internal pipeline minus the tamper step:
    //   pick keys → digest → sign → encode → submit.
    const fee = await client.getExecuteFee();
    const target = zeroAddress;
    const value = 0n;
    const data: Hex = "0x";

    const currentKey = await client.getHeadTransactionKey();
    const nextKey = signer.generateKeyPair(toHex(vaultId)).publicKey;

    const digest = executeDigest(
      walletAddress,
      BigInt(foundry.id),
      currentKey.publicSeed,
      currentKey.publicKeyHash,
      nextKey.publicSeed,
      nextKey.publicKeyHash,
      target,
      value,
      opdataHash(data),
      fee
    );

    // Sign correctly, then tamper element 0. Note: `signer.sign` burns
    // the key in-memory. The on-chain tx will revert with InvalidSignature
    // before the contract rotates, so the on-chain state stays consistent;
    // the signer's burned-key set is the only thing left dirty (and that's
    // the correct WOTS+ semantic — once a sig exists, the key is dead).
    const sigElements: Hex[] = signer.sign(
      digest,
      toHex(vaultId),
      currentKey.publicSeed
    );
    sigElements[0] = ("0x" + "00".repeat(32)) as Hex;
    const pqSig: WinternitzElements = { elements: sigElements };

    const tamperedPayload = encodeExecute(
      currentKey,
      nextKey,
      pqSig,
      target,
      value,
      data
    );

    // Submit raw — bypasses the SDK's `executeWithPayload` (which would
    // re-sign with a fresh sig, hiding the tamper). Simulation should
    // catch the wallet's `_verifyAndRotate` rejection and decode to
    // `InvalidSignatureError`.
    let caught: unknown = null;
    try {
      await withDecodedError(
        stack.publicClient.simulateContract({
          address: walletAddress,
          abi: quipWalletAbi,
          functionName: "execute",
          args: [tamperedPayload],
          account: stack.account.address,
        })
      );
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(InvalidSignatureError);
  }, 30_000);
});
