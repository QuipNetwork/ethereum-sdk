// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pins the ERC-1271 never-revert property of `ShrincsWallet.isValidSignature`
// against adversarial input, on a real deployment. The signature is a
// fixed-layout envelope, so the wallet's first check is its exact length; every
// rejection returns the ERC-1271 failure magic instead of reverting.

import { type Address, type Hex, concat, keccak256, toHex } from "viem";

import { shrincsWalletAbi } from "../abi/ShrincsWallet.js";
import {
  ERC1271_MAGIC,
  ERC1271_SIGNATURE_BYTES,
  ERC1271_VERSION,
  SHRINCS_PROFILE_ID,
  STATELESS_PAYLOAD_BYTES,
} from "../constants.js";
import { encodeLegacyErc1271Signature } from "../shrincsCodec.js";
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

const filled = (n: number, byte: string): Hex => ("0x" + byte.repeat(n)) as Hex;

/// A header-valid envelope around the given ECDSA half and an all-zero
/// `PK ‖ PQ` payload: exact length, right magic / version / profile.
const zeroPayloadEnvelope = (ecdsaSig: Hex): Hex =>
  concat([
    ERC1271_MAGIC,
    toHex(ERC1271_VERSION, { size: 1 }),
    SHRINCS_PROFILE_ID,
    ecdsaSig,
    filled(STATELESS_PAYLOAD_BYTES, "00"),
  ]);

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

  // Adversary-reachable inputs: none carries a valid owner ECDSA half.
  const adversarial: Array<{ name: string; blob: Hex }> = [
    { name: "empty", blob: "0x" },
    { name: "short junk", blob: filled(0x100, "ff") },
    { name: "one byte short of the envelope", blob: filled(ERC1271_SIGNATURE_BYTES - 1, "00") },
    { name: "one byte past the envelope", blob: filled(ERC1271_SIGNATURE_BYTES + 1, "00") },
    { name: "exact length, all zero (wrong header)", blob: filled(ERC1271_SIGNATURE_BYTES, "00") },
    { name: "exact length, all 0xff (wrong header)", blob: filled(ERC1271_SIGNATURE_BYTES, "ff") },
    { name: "valid header, junk ECDSA, zero payload", blob: zeroPayloadEnvelope(filled(65, "11")) },
    {
      name: "pre-0.4.0 ABI-encoded signature",
      blob: encodeLegacyErc1271Signature({
        publicKey: {
          statefulPublicKey: "0x",
          publicKeyCommitment: "0x",
          pkSeed: "0x",
          hypertreeRoot: "0x",
        },
        signature: { fors: { randomizer: "0x", counter: 0, entries: [] }, hypertree: [] },
        ecdsaSig: filled(65, "11"),
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

  // Owner-reachable path: a VALID owner ECDSA half passes the gate, so the
  // all-zero payload reaches the external verifier, which must answer "invalid"
  // rather than revert.
  it("does not revert when a valid owner ECDSA reaches the verifier with a zero payload", async () => {
    const owner: Address = DEFAULT_ACCOUNT.address;
    expect(owner.toLowerCase()).toBe(
      (await wallet.client.getWalletState()).owner.toLowerCase()
    );

    const target = await wallet.client.quipSignedHashEcdsaTarget(hash);
    const ecdsaSig = await DEFAULT_ACCOUNT.sign({ hash: target });

    const blob = zeroPayloadEnvelope(ecdsaSig);
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
    // The SDK built the fixed-layout envelope the wallet reports it accepts.
    expect(blob.length).toBe(2 + 2 * ERC1271_SIGNATURE_BYTES);
    expect(await wallet.client.getErc1271Version()).toBe(ERC1271_VERSION);
    // Real SHRINCS keygen + signErc1271 (SPHINCS+) runs well past jest's 5s
    // default; the other suites keep this cost in beforeAll, this test doesn't.
  }, 30_000);
});
