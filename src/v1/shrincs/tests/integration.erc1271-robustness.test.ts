// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pins the ERC-1271 never-revert property of `ShrincsWallet.isValidSignature`
// against adversarial input. `Codec.decodeErc1271Signature` is pure assembly
// pointer math after a `length < 0x60` guard, so it cannot itself revert on any
// >=0x60 blob (`calldataload` past calldatasize reads as zero). The only
// revert-prone surface — the nested dynamic-calldata reads inside
// `SHRINCS.verifyStateless` — sits BEHIND the classical owner ECDSA check, which
// runs first and short-circuits. So an adversary (anyone lacking the owner key)
// can never drive the fragile decode: every adversary-reachable input must
// return the ERC-1271 failure magic `0xffffffff`, never revert. ERC-1271
// consumers staticcall this; a revert would be a DoS on the relying contract.

import { type Address, type Hex, keccak256, toHex } from "viem";

import { shrincsWalletAbi } from "../abi/ShrincsWallet.js";
import { encodeErc1271Signature } from "../shrincsCodec.js";
import { type StatelessSignature } from "../types.js";
import {
  DEFAULT_ACCOUNT,
  createFreshShrincsWallet,
  setupShrincsAnvilStack,
  stopShrincsAnvilStack,
  type ShrincsAnvilStack,
  type FreshShrincsWallet,
} from "./utils/shrincsAnvilFixture.js";

const PORT = 8561;
const FAIL_MAGIC = "0xffffffff";

// A structurally well-formed but semantically empty SHRINCS stateless signature
// — valid ABI (proper offsets, zero-length dynamic fields), so decoding it never
// reads out of bounds; it simply fails verification.
const EMPTY_STATELESS: StatelessSignature = {
  fors: { randomizer: "0x", counter: 0, entries: [] },
  hypertree: [],
};

const EMPTY_PUBLIC_KEY = {
  statefulPublicKey: "0x" as Hex,
  publicKeyCommitment: "0x" as Hex,
  pkSeed: "0x" as Hex,
  hypertreeRoot: "0x" as Hex,
};

let stack: ShrincsAnvilStack;
let wallet: FreshShrincsWallet;

/// Call the wallet's ERC-1271 entrypoint RAW (not via the SDK client, which
/// would wrap a revert in a typed error) so we can observe revert-vs-return
/// directly. Returns the bytes4, or the sentinel "THREW" if it reverted.
async function callIsValidSignature(hash: Hex, signature: Hex): Promise<Hex | "THREW"> {
  try {
    return (await stack.publicClient.readContract({
      address: wallet.walletAddress,
      abi: shrincsWalletAbi,
      functionName: "isValidSignature",
      args: [hash, signature],
    })) as Hex;
  } catch {
    return "THREW";
  }
}

beforeAll(async () => {
  stack = await setupShrincsAnvilStack({ port: PORT });
  wallet = await createFreshShrincsWallet(stack, 0x5a, { maxSignatures: 4 });
}, 120_000);

afterAll(async () => {
  if (stack) await stopShrincsAnvilStack(stack);
});

describe("ShrincsWallet.isValidSignature never-revert robustness", () => {
  const hash = keccak256(toHex("erc1271 robustness probe message"));

  // Adversary-reachable inputs: none of these carry a valid owner ECDSA sig, so
  // they short-circuit at the ECDSA gate before reaching the SHRINCS decode.
  const adversarial: Array<{ name: string; blob: Hex }> = [
    { name: "empty (length 0 < 0x60)", blob: "0x" },
    { name: "short (0x40 zero bytes < 0x60)", blob: ("0x" + "00".repeat(0x40)) as Hex },
    { name: "0x60 zero bytes (all offsets -> 0)", blob: ("0x" + "00".repeat(0x60)) as Hex },
    { name: "0x60 0xff bytes (offsets wrap huge)", blob: ("0x" + "ff".repeat(0x60)) as Hex },
    { name: "0x100 0xff bytes", blob: ("0x" + "ff".repeat(0x100)) as Hex },
    {
      name: "offsets point past calldatasize",
      // three head words: pk/sig/ecdsa offsets all = 0xffff..ff (wrap to wild
      // pointers); reads there return zero -> empty -> ECDSA fails -> fail magic.
      blob: ("0x" + "ff".repeat(0x20).repeat(3)) as Hex,
    },
    {
      name: "huge ecdsaSig length word",
      // head: pk=0, sig=0, ecdsa-offset=0x60; at 0x60 a length word of all-ff so
      // ecdsaSig.length is enormous -> tryRecover sees length != 64/65 -> zero.
      blob: ("0x" +
        "00".repeat(0x20) +
        "00".repeat(0x20) +
        toHex(0x60, { size: 32 }).slice(2) +
        "ff".repeat(0x20)) as Hex,
    },
    {
      name: "deterministic pseudo-random 0xc8 bytes",
      blob: ("0x" +
        Array.from({ length: 0xc8 }, (_, i) =>
          ((i * 131 + 17) & 0xff).toString(16).padStart(2, "0")
        ).join("")) as Hex,
    },
    {
      name: "well-formed envelope, empty SHRINCS + no ECDSA",
      blob: encodeErc1271Signature({
        publicKey: EMPTY_PUBLIC_KEY,
        signature: EMPTY_STATELESS,
        ecdsaSig: "0x",
      }),
    },
    {
      name: "well-formed envelope, empty SHRINCS + junk 65-byte ECDSA",
      blob: encodeErc1271Signature({
        publicKey: EMPTY_PUBLIC_KEY,
        signature: EMPTY_STATELESS,
        ecdsaSig: ("0x" + "11".repeat(65)) as Hex,
      }),
    },
  ];

  it.each(adversarial)(
    "returns fail magic without reverting: $name",
    async ({ blob }) => {
      const result = await callIsValidSignature(hash, blob);
      expect(result).not.toBe("THREW");
      expect(result).toBe(FAIL_MAGIC);
    }
  );

  it("the SDK client surfaces a clean `false` (not a thrown error) for garbage", async () => {
    await expect(
      wallet.client.isValidSignature(hash, ("0x" + "ff".repeat(0x80)) as Hex)
    ).resolves.toBe(false);
  });

  // Owner-reachable path: a VALID owner ECDSA sig over the EIP-712 target passes
  // the gate and reaches SHRINCS.verifyStateless. With a WELL-FORMED (empty)
  // stateless blob the nested calldata reads stay in bounds, so verification
  // fails cleanly rather than reverting — proving even past the gate, in-spec
  // input is non-reverting.
  it("does not revert when a valid owner ECDSA reaches the SHRINCS verify with an empty (well-formed) stateless sig", async () => {
    const owner: Address = DEFAULT_ACCOUNT.address;
    expect(owner.toLowerCase()).toBe(
      (await wallet.client.getWalletState()).owner.toLowerCase()
    );

    const target = await wallet.client.quipSignedHashEcdsaTarget(hash);
    const ecdsaSig = await DEFAULT_ACCOUNT.sign({ hash: target });

    const blob = encodeErc1271Signature({
      publicKey: EMPTY_PUBLIC_KEY,
      signature: EMPTY_STATELESS,
      ecdsaSig,
    });
    const result = await callIsValidSignature(hash, blob);
    expect(result).not.toBe("THREW");
    expect(result).toBe(FAIL_MAGIC); // ECDSA ok, SHRINCS verify fails cleanly
  });

  // Sanity anchor: the same wallet, given a GENUINE signErc1271 blob over the
  // same hash, returns the success magic — so the battery above is rejecting
  // bad input, not a wallet that rejects everything.
  it("accepts a genuine signErc1271 blob (success magic) — battery isn't a tautology", async () => {
    const erc1271KeyPair = wallet.signer.recoverKeyPair(
      wallet.erc1271DerivationIndex,
      {
        maxSignatures: wallet.maxSignatures,
      }
    );
    const blob = await wallet.client.signErc1271({
      hash,
      erc1271KeyPair,
      owner: DEFAULT_ACCOUNT,
    });
    expect(await wallet.client.isValidSignature(hash, blob)).toBe(true);
    // Real SHRINCS keygen + signErc1271 (SPHINCS+) runs well past jest's 5s
    // default; the other suites keep this cost in beforeAll, this test doesn't.
  }, 30_000);
});
