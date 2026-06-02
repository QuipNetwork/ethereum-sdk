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
// SDK ↔ contract parity for the ERC-1271 surface:
//   1. `quipSignedHashEcdsaTarget(wallet, chainId, hash)` (SDK) matches
//      `wallet.quipSignedHashEcdsaTarget(hash)` (contract) byte-for-byte
//      across fixed and fuzzed hashes.
//   2. `QuipWalletClient.signErc1271(...)` produces a 2273-byte blob the
//      live contract accepts (returns the EIP-1271 magic `0x1626ba7e`).
//   3. Signing with a non-owner classical key produces a blob the wallet
//      rejects (magic `0xffffffff`).
import {
  describe,
  test,
  expect,
  beforeAll,
  afterAll,
} from "@jest/globals";
import { type Hex, toHex, keccak256 } from "viem";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

import { quipWalletAbi } from "../abi/QuipWallet.js";
import { quipSignedHashEcdsaTarget } from "../wotsCodec.js";
import {
  ANVIL_PORTS,
  type AnvilStack,
  createFreshWallet,
  setupAnvilStack,
  stopAnvilStack,
} from "./utils/anvilFixture.js";

// Anvil prefunded dev account #0 — the wallet's `owner()` in
// `createFreshWallet`. Its private key is what the EIP-712 wrap must be
// signed under for the contract to recover `owner()`.
const OWNER_PRIV =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const ownerAccount = privateKeyToAccount(OWNER_PRIV);

// Anvil prefunded dev account #1 — the non-owner used to prove the ECDSA
// gate rejects signatures from anyone but `owner()`.
const STRANGER_PRIV =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as const;
const strangerAccount = privateKeyToAccount(STRANGER_PRIV);

const MAGIC = "0x1626ba7e" as const;
const FAIL = "0xffffffff" as const;

let stack: AnvilStack;

beforeAll(async () => {
  stack = await setupAnvilStack({
    port: ANVIL_PORTS.erc1271,
    deployEntryPoint: false,
  });
}, 60_000);

afterAll(async () => {
  await stopAnvilStack(stack);
}, 10_000);

describe("ERC-1271 EIP-712 wrap parity", () => {
  test("SDK quipSignedHashEcdsaTarget matches contract view (fixed hashes)", async () => {
    const { walletAddress } = await createFreshWallet(stack, 0xe0);

    const samples: Hex[] = [
      keccak256(toHex("permit2-style")),
      keccak256(toHex("seaport-order")),
      ("0x" + "00".repeat(32)) as Hex,
      ("0x" + "ff".repeat(32)) as Hex,
    ];

    for (const hash of samples) {
      const offChain = quipSignedHashEcdsaTarget(
        walletAddress,
        BigInt(foundry.id),
        hash
      );
      const onChain = (await stack.publicClient.readContract({
        address: walletAddress,
        abi: quipWalletAbi,
        functionName: "quipSignedHashEcdsaTarget",
        args: [hash],
      })) as Hex;
      expect(offChain).toBe(onChain);
    }
  }, 30_000);

  test("SDK quipSignedHashEcdsaTarget matches contract view (randomized)", async () => {
    const { walletAddress } = await createFreshWallet(stack, 0xe1);

    for (let i = 0; i < 12; ++i) {
      const hash = keccak256(toHex(`fuzz-${i}-${Date.now()}`));
      const offChain = quipSignedHashEcdsaTarget(
        walletAddress,
        BigInt(foundry.id),
        hash
      );
      const onChain = (await stack.publicClient.readContract({
        address: walletAddress,
        abi: quipWalletAbi,
        functionName: "quipSignedHashEcdsaTarget",
        args: [hash],
      })) as Hex;
      expect(offChain).toBe(onChain);
    }
  }, 30_000);

  test("SDK target binds to wallet address", async () => {
    const a = await createFreshWallet(stack, 0xe2);
    const b = await createFreshWallet(stack, 0xe3);
    expect(a.walletAddress).not.toBe(b.walletAddress);

    const hash = keccak256(toHex("wallet-binding"));
    const targetA = quipSignedHashEcdsaTarget(
      a.walletAddress,
      BigInt(foundry.id),
      hash
    );
    const targetB = quipSignedHashEcdsaTarget(
      b.walletAddress,
      BigInt(foundry.id),
      hash
    );
    expect(targetA).not.toBe(targetB);
  }, 30_000);
});

describe("QuipWalletClient.signErc1271 end-to-end", () => {
  test("owner-signed blob is accepted by isValidSignature", async () => {
    const { client, walletAddress, verificationKeys } = await createFreshWallet(
      stack,
      0xe4
    );

    // The canonical integrator pattern: two lines, no domain literals.
    const hash = keccak256(toHex("erc1271-happy-path"));
    const ecdsaSig = await ownerAccount.signTypedData(
      client.erc1271TypedData(hash)
    );
    const blob = await client.signErc1271({
      hash,
      verifier: verificationKeys[0]!,
      ecdsaSig,
    });

    const result = (await stack.publicClient.readContract({
      address: walletAddress,
      abi: quipWalletAbi,
      functionName: "isValidSignature",
      args: [hash, blob],
    })) as Hex;

    expect(result).toBe(MAGIC);
  }, 30_000);

  test("stranger-signed blob is rejected by isValidSignature", async () => {
    const { client, walletAddress, verificationKeys } = await createFreshWallet(
      stack,
      0xe5
    );

    const hash = keccak256(toHex("erc1271-stranger-rejection"));
    // Non-owner key signs the (correctly formed) EIP-712 envelope; the
    // wallet's ECDSA recovery yields the stranger's address, not
    // `owner()`, so isValidSignature returns `0xffffffff`.
    const ecdsaSig = await strangerAccount.signTypedData(
      client.erc1271TypedData(hash)
    );
    const blob = await client.signErc1271({
      hash,
      verifier: verificationKeys[0]!,
      ecdsaSig,
    });

    const result = (await stack.publicClient.readContract({
      address: walletAddress,
      abi: quipWalletAbi,
      functionName: "isValidSignature",
      args: [hash, blob],
    })) as Hex;

    expect(result).toBe(FAIL);
  }, 30_000);

  test("signing the raw hash (no EIP-712 wrap) is rejected", async () => {
    const { client, walletAddress, verificationKeys } = await createFreshWallet(
      stack,
      0xe6
    );

    const hash = keccak256(toHex("erc1271-missing-eip712-wrap"));
    // Caller bypasses the helper and signs `hash` directly with no wrap.
    const ecdsaSig = await ownerAccount.sign({ hash });
    const blob = await client.signErc1271({
      hash,
      verifier: verificationKeys[0]!,
      ecdsaSig,
    });

    const result = (await stack.publicClient.readContract({
      address: walletAddress,
      abi: quipWalletAbi,
      functionName: "isValidSignature",
      args: [hash, blob],
    })) as Hex;

    expect(result).toBe(FAIL);
  }, 30_000);
});

describe("EIP-712 compliance", () => {
  // The compliance question is: can a standard EIP-712 tool (no Quip SDK)
  // produce a signature this wallet accepts? If `viem.signTypedData` with
  // the domain advertised by `eip712Domain()` and the `QuipSignedHash`
  // type works, the wallet is canonically EIP-712 compliant.
  test("eip712Domain() advertises the domain used by signature verification", async () => {
    const { walletAddress } = await createFreshWallet(stack, 0xe7);

    const domain = (await stack.publicClient.readContract({
      address: walletAddress,
      abi: quipWalletAbi,
      functionName: "eip712Domain",
    })) as readonly [
      Hex,
      string,
      string,
      bigint,
      Hex,
      Hex,
      readonly bigint[],
    ];
    const [fields, name, version, chainId, verifyingContract, salt, extensions] =
      domain;

    // Per ERC-5267, `fields = 0x0f` means name, version, chainId,
    // verifyingContract are all populated (bits 0-3 set).
    expect(fields).toBe("0x0f");
    expect(name).toBe("QuipWallet");
    expect(version).toBe("1");
    expect(chainId).toBe(BigInt(foundry.id));
    expect(verifyingContract.toLowerCase()).toBe(walletAddress.toLowerCase());
    expect(salt).toBe(("0x" + "00".repeat(32)) as Hex);
    expect(extensions).toEqual([]);
  }, 30_000);

  test("viem.signTypedData over the canonical QuipSignedHash struct is accepted", async () => {
    const { client, walletAddress, verificationKeys } = await createFreshWallet(
      stack,
      0xe8
    );

    const hash = keccak256(toHex("erc1271-eip712-canonical"));

    // Produce the ECDSA half via viem's canonical EIP-712 signer — the
    // same code path Permit2, Seaport, MetaMask, hardware wallets, etc.
    // would take. The integrator only needs to know the four EIP-712
    // primitives: domain, types, primaryType, message. By spelling them
    // out explicitly here (rather than calling `erc1271TypedData(...)`),
    // this test proves the wallet accepts blobs signed by an integrator
    // who has never touched the Quip SDK.
    const ecdsaSig = await ownerAccount.signTypedData({
      domain: {
        name: "QuipWallet",
        version: "1",
        chainId: foundry.id,
        verifyingContract: walletAddress,
      },
      types: { QuipSignedHash: [{ name: "hash", type: "bytes32" }] },
      primaryType: "QuipSignedHash",
      message: { hash },
    });
    const blob = await client.signErc1271({
      hash,
      verifier: verificationKeys[0]!,
      ecdsaSig,
    });

    const result = (await stack.publicClient.readContract({
      address: walletAddress,
      abi: quipWalletAbi,
      functionName: "isValidSignature",
      args: [hash, blob],
    })) as Hex;

    expect(result).toBe(MAGIC);
  }, 30_000);

  test("viem.signTypedData using the wrong chainId is rejected", async () => {
    const { client, walletAddress, verificationKeys } = await createFreshWallet(
      stack,
      0xe9
    );

    const hash = keccak256(toHex("erc1271-wrong-chainid"));
    const ecdsaSig = await ownerAccount.signTypedData({
      domain: {
        name: "QuipWallet",
        version: "1",
        chainId: foundry.id + 1, // wrong chain
        verifyingContract: walletAddress,
      },
      types: { QuipSignedHash: [{ name: "hash", type: "bytes32" }] },
      primaryType: "QuipSignedHash",
      message: { hash },
    });
    const blob = await client.signErc1271({
      hash,
      verifier: verificationKeys[0]!,
      ecdsaSig,
    });

    const result = (await stack.publicClient.readContract({
      address: walletAddress,
      abi: quipWalletAbi,
      functionName: "isValidSignature",
      args: [hash, blob],
    })) as Hex;

    expect(result).toBe(FAIL);
  }, 30_000);

  test("viem.signTypedData using a sibling wallet's address is rejected (replay protection)", async () => {
    const target = await createFreshWallet(stack, 0xea);
    const sibling = await createFreshWallet(stack, 0xeb);
    expect(target.walletAddress).not.toBe(sibling.walletAddress);

    const hash = keccak256(toHex("erc1271-sibling-replay"));
    // Sign FOR the sibling wallet (verifyingContract = sibling.walletAddress),
    // then try to use the blob against `target`. Even though the same
    // EOA (ownerAccount) signs both, the EIP-712 wrap binds to the
    // wallet address — so the recovered signer on `target` will be
    // garbage, NOT the owner.
    const ecdsaSig = await ownerAccount.signTypedData(
      sibling.client.erc1271TypedData(hash)
    );
    const blob = await target.client.signErc1271({
      hash,
      verifier: target.verificationKeys[0]!,
      ecdsaSig,
    });

    const result = (await stack.publicClient.readContract({
      address: target.walletAddress,
      abi: quipWalletAbi,
      functionName: "isValidSignature",
      args: [hash, blob],
    })) as Hex;

    expect(result).toBe(FAIL);
  }, 30_000);

  test("erc1271TypedData() returns the exact envelope the contract verifies", async () => {
    // Cross-check: the helper's output, signed via signTypedData, must
    // recover to the same address as the integrator-handwritten envelope
    // — i.e., the helper hasn't silently drifted from the spec.
    const { client, walletAddress, verificationKeys } = await createFreshWallet(
      stack,
      0xec
    );

    const hash = keccak256(toHex("erc1271-helper-parity"));

    const handwritten = await ownerAccount.signTypedData({
      domain: {
        name: "QuipWallet",
        version: "1",
        chainId: foundry.id,
        verifyingContract: walletAddress,
      },
      types: { QuipSignedHash: [{ name: "hash", type: "bytes32" }] },
      primaryType: "QuipSignedHash",
      message: { hash },
    });
    const fromHelper = await ownerAccount.signTypedData(
      client.erc1271TypedData(hash)
    );

    // Byte-for-byte equality proves the helper produces the canonical
    // EIP-712 envelope — no domain drift, no struct drift.
    expect(fromHelper).toBe(handwritten);

    // Sanity: both halves of the test get accepted by the contract.
    const blob = await client.signErc1271({
      hash,
      verifier: verificationKeys[0]!,
      ecdsaSig: fromHelper,
    });
    const result = (await stack.publicClient.readContract({
      address: walletAddress,
      abi: quipWalletAbi,
      functionName: "isValidSignature",
      args: [hash, blob],
    })) as Hex;
    expect(result).toBe(MAGIC);
  }, 30_000);
});
