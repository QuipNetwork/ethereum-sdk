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
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  createPublicClient,
  createWalletClient,
  http,
  parseEventLogs,
  toHex,
  zeroAddress,
} from "viem";
import { createAnvil } from "@viem/anvil";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { quipFactoryAbi } from "./abi/QuipFactory.js";
import { quipWalletAbi } from "./abi/QuipWallet.js";
import { QuipSigner } from "./signer.js";
import { QuipWalletClient } from "./walletClient.js";
import {
  InvalidSignatureError,
  SimulationError,
  UnknownContractError,
} from "./errors.js";
import { withDecodedError } from "./internal/decodeError.js";
import {
  encodeExecute,
  executeDigest,
  opdataHash,
  type WinternitzAddress,
  type WinternitzElements,
  TRANSACTION_KEY_INIT_AMOUNT,
  RECOVERY_KEY_AMOUNT,
  encodeInit,
} from "./wotsCodec.js";

// ─── Forge artifacts ────────────────────────────────────────────────
const factoryArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/QuipFactory.sol/QuipFactory.json"),
    "utf8"
  )
);
const factoryBytecode = factoryArtifact.bytecode.object as Hex;

const walletArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/QuipWallet.sol/QuipWallet.json"),
    "utf8"
  )
);
const walletUnlinkedBytecode = walletArtifact.bytecode.object as string;
const quipWalletDeployAbi = walletArtifact.abi;

const wotsPlusArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/WOTSPlus.sol/WOTSPlus.json"),
    "utf8"
  )
);
const wotsPlusBytecode = wotsPlusArtifact.bytecode.object as Hex;
const wotsPlusAbi = wotsPlusArtifact.abi;

function linkWalletBytecode(libAddress: Address): Hex {
  const refs =
    walletArtifact.bytecode.linkReferences as Record<
      string,
      Record<string, Array<{ start: number; length: number }>>
    >;
  let hex = walletUnlinkedBytecode.replace(/^0x/, "");
  const addrPlain = libAddress.replace(/^0x/, "").toLowerCase();
  for (const file of Object.values(refs)) {
    for (const libRefs of Object.values(file)) {
      for (const ref of libRefs) {
        const hexStart = ref.start * 2;
        const hexLen = ref.length * 2;
        hex =
          hex.slice(0, hexStart) + addrPlain + hex.slice(hexStart + hexLen);
      }
    }
  }
  return ("0x" + hex) as Hex;
}

// Anvil's prefunded dev accounts. We use #0 as the wallet owner and #1
// as the "stranger" (non-owner) to test the ECDSA gate.
const OWNER_PRIV =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const STRANGER_PRIV =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const owner = privateKeyToAccount(OWNER_PRIV);
const stranger = privateKeyToAccount(STRANGER_PRIV);

const anvil = createAnvil({ port: 8557 });
let publicClient: PublicClient;
let ownerWallet: WalletClient;
let strangerWallet: WalletClient;
let factoryAddress: Address;

const MAX_FEE = 10n ** 16n;

function buildInitPayload(signer: QuipSigner, vaultId: Hex) {
  const disaster = signer.generateKeyPair(vaultId).publicKey;
  const ownership = signer.generateKeyPair(vaultId).publicKey;
  const transactionKeys = Array.from(
    { length: TRANSACTION_KEY_INIT_AMOUNT },
    () => signer.generateKeyPair(vaultId).publicKey
  );
  const recoveryKeys = Array.from({ length: RECOVERY_KEY_AMOUNT }, () =>
    signer.generateKeyPair(vaultId).publicKey
  );
  return encodeInit(disaster, ownership, transactionKeys, recoveryKeys);
}

async function createFreshWallet(seedByte: number): Promise<{
  signer: QuipSigner;
  vaultId: Uint8Array;
  client: QuipWalletClient;
  walletAddress: Address;
}> {
  const quantumSecret = new Uint8Array(32).fill(seedByte);
  const signer = new QuipSigner(quantumSecret);
  const vaultId = new Uint8Array(32).fill(seedByte);
  const initPayload = buildInitPayload(signer, toHex(vaultId));

  const hash = await ownerWallet.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "deployLatestWalletProxy",
    args: [toHex(vaultId), owner.address, initPayload],
    account: owner,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const logs = parseEventLogs({
    abi: quipFactoryAbi,
    logs: receipt.logs,
    eventName: "QuipCreated",
  });
  const walletAddress = logs[0].args.quip;

  const client = new QuipWalletClient(
    signer,
    vaultId,
    walletAddress,
    publicClient,
    ownerWallet,
    owner.address,
    foundry.id
  );
  return { signer, vaultId, client, walletAddress };
}

beforeAll(async () => {
  await anvil.start();
  const transport = http(`http://127.0.0.1:${anvil.port}`);
  publicClient = createPublicClient({ chain: foundry, transport });
  ownerWallet = createWalletClient({ chain: foundry, transport, account: owner });
  strangerWallet = createWalletClient({
    chain: foundry,
    transport,
    account: stranger,
  });

  // Deploy QuipFactory.
  const factoryHash = await ownerWallet.deployContract({
    abi: quipFactoryAbi,
    bytecode: factoryBytecode,
    args: [owner.address, MAX_FEE],
    account: owner,
    chain: foundry,
  });
  const factoryReceipt = await publicClient.waitForTransactionReceipt({
    hash: factoryHash,
  });
  factoryAddress = factoryReceipt.contractAddress!;

  // Deploy WOTSPlus lib + linked wallet impl.
  const wotsHash = await ownerWallet.deployContract({
    abi: wotsPlusAbi,
    bytecode: wotsPlusBytecode,
    account: owner,
    chain: foundry,
  });
  const wotsReceipt = await publicClient.waitForTransactionReceipt({
    hash: wotsHash,
  });
  const wotsAddress = wotsReceipt.contractAddress!;

  const walletBytecode = linkWalletBytecode(wotsAddress);
  const implHash = await ownerWallet.deployContract({
    abi: quipWalletDeployAbi,
    bytecode: walletBytecode,
    args: [factoryAddress],
    account: owner,
    chain: foundry,
  });
  const implReceipt = await publicClient.waitForTransactionReceipt({
    hash: implHash,
  });
  const walletImplAddress = implReceipt.contractAddress!;

  const vetHash = await ownerWallet.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "vetImplementation",
    args: [walletImplAddress],
    account: owner,
  });
  await publicClient.waitForTransactionReceipt({ hash: vetHash });
}, 60_000);

afterAll(async () => {
  await anvil.stop().catch(() => {});
}, 10_000);

describe("Dual-signature contract on execute(bytes)", () => {
  test("happy path: owner ECDSA + valid WOTS+ succeeds", async () => {
    const { client, walletAddress } = await createFreshWallet(0xd0);

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
    const { signer, vaultId, walletAddress } = await createFreshWallet(0xd1);

    // Construct a QuipWalletClient bound to `stranger` (non-owner EOA)
    // but using the real signer/vaultId so the WOTS+ half is valid. The
    // EOA mismatch is what should trip the gate — proving the ECDSA
    // outer is independently enforced.
    const strangerClient = new QuipWalletClient(
      signer,
      vaultId,
      walletAddress,
      publicClient,
      strangerWallet,
      stranger.address,
      foundry.id
    );

    // Simulate-before-send catches the revert. The wallet uses Solady's
    // `Ownable` which reverts with `Unauthorized()` — not in our typed
    // error registry, so it surfaces as `UnknownContractError` with the
    // error name preserved.
    let caught: unknown = null;
    try {
      await strangerClient.executeWithPayload(zeroAddress, 0n, "0x");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(SimulationError);
    const sim = caught as SimulationError;
    // The decoded inner should reflect the contract-level revert.
    // Solady `Unauthorized()` has no args and isn't in our typed registry
    // → UnknownContractError carrying the name "Unauthorized".
    expect(sim.decodedError).toBeInstanceOf(UnknownContractError);
    const unknown = sim.decodedError as UnknownContractError;
    expect(unknown.errorName).toBe("Unauthorized");
  }, 30_000);

  test("wrong WOTS+: owner ECDSA + tampered WOTS+ sig reverts via _verifyAndRotate", async () => {
    const { signer, vaultId, client, walletAddress } = await createFreshWallet(
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
        publicClient.simulateContract({
          address: walletAddress,
          abi: quipWalletAbi,
          functionName: "execute",
          args: [tamperedPayload],
          account: owner.address,
        })
      );
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(InvalidSignatureError);
  }, 30_000);
});
