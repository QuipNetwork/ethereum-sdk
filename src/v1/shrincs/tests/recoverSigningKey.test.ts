// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  keccak256,
  toHex,
} from "viem";

import { CommitmentMismatchError } from "../errors.js";
import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";
import { ShrincsWalletClient } from "../shrincsWalletClient.js";

const WALLET = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" as Address;
const VAULT_ID = `0x${"00".repeat(32)}` as Hex;
const CHAIN_ID = 31337;
const MAX_SIG = 8;
// hashsigs-wasm enforces >= 32-byte seeds (ERR_SEED_TOO_SHORT) — hash the label to 32 bytes.
const seed = (s: string) => keccak256(toHex(new TextEncoder().encode(s)));

// `recoverSigningKey` is private; reach it through a narrow typed view. The
// injected-keypair path touches neither the public nor wallet client, so bare
// casts suffice for those constructor params.
type RecoverSigningKey = (
  maxSignatures: number,
  installedCommitment: Hex
) => ShrincsKeyPair;

function recoverSigningKey(
  client: ShrincsWalletClient,
  installedCommitment: Hex
): ShrincsKeyPair {
  const fn = (client as unknown as { recoverSigningKey: RecoverSigningKey })
    .recoverSigningKey;
  return fn.call(client, MAX_SIG, installedCommitment);
}

function makeClient(keypair: ShrincsKeyPair): ShrincsWalletClient {
  return new ShrincsWalletClient({
    walletAddress: WALLET,
    publicClient: {} as PublicClient,
    walletClient: {} as WalletClient,
    keypair,
    vaultId: VAULT_ID,
    chainId: CHAIN_ID,
    account: WALLET,
  });
}

describe("ShrincsWalletClient.recoverSigningKey (injected keypair)", () => {
  let keypair: ShrincsKeyPair;

  beforeAll(async () => {
    const signer = await ShrincsSigner.create(
      new TextEncoder().encode("any master")
    );
    keypair = signer.keygenFromSeedHex(seed("injected keypair seed"), {
      maxSignatures: MAX_SIG,
    });
  });

  it("throws CommitmentMismatchError when the injected keypair does not match the installed commitment", () => {
    const client = makeClient(keypair);
    const installed = `0x${"ff".repeat(32)}` as Hex;
    expect(installed.toLowerCase()).not.toBe(
      keypair.publicKeyCommitment.toLowerCase()
    );
    expect(() => recoverSigningKey(client, installed)).toThrow(
      CommitmentMismatchError
    );
  });

  it("returns the injected keypair when its commitment matches (case-insensitively)", () => {
    const client = makeClient(keypair);
    const installed = keypair.publicKeyCommitment.toUpperCase() as Hex;
    expect(recoverSigningKey(client, installed)).toBe(keypair);
  });
});

describe("ShrincsWalletClient.recoverSigningKey (signer fallback)", () => {
  it("throws when the signer fallback is reached without derivationIndex", async () => {
    const signer = await ShrincsSigner.create(
      new TextEncoder().encode("any master")
    );
    const client = new ShrincsWalletClient({
      walletAddress: WALLET,
      publicClient: {} as PublicClient,
      walletClient: {} as WalletClient,
      signer,
      vaultId: VAULT_ID,
      chainId: CHAIN_ID,
      account: WALLET,
    });
    expect(() =>
      recoverSigningKey(client, `0x${"ff".repeat(32)}` as Hex)
    ).toThrow("ShrincsWalletClient has no derivationIndex to recover a keypair with");
  });
});
