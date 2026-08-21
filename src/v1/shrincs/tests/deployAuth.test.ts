// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type Address, type Hex, keccak256, toHex } from "viem";

import { buildDeployAuthorization, buildDeployContext } from "../deployAuth.js";
import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";
import { type StatefulSignature } from "../types.js";

const FACTORY = "0xE567d318819c067c26fC1E44D04beD2b4FE93BCC" as Address;
const OWNER = "0x00000000000000000000000000000000000000a1" as Address;
const ERC1271 = keccak256(toHex("erc1271-commitment"));
const seed = (s: string): Hex => keccak256(toHex(new TextEncoder().encode(s)));

let mainKey: ShrincsKeyPair;

beforeAll(async () => {
  const signer = await ShrincsSigner.create(new TextEncoder().encode("master"));
  mainKey = signer.keygenFromSeedHex(seed("deploy auth main key"), {
    maxSignatures: 8,
  });
});

const baseParams = (over: Partial<Parameters<typeof buildDeployAuthorization>[0]> = {}) => ({
  mainKey,
  chainId: 1,
  factoryAddress: FACTORY,
  vaultId: seed("vault"),
  owner: OWNER,
  erc1271Commitment: ERC1271,
  quipDeployChainIndex: 3,
  mode: "stateful" as const,
  ...over,
});

describe("buildDeployAuthorization (e3r)", () => {
  it("produces a stateful signature that verifies against the main key", () => {
    const params = baseParams();
    const { context, signature } = buildDeployAuthorization(params);
    const message = mainKey.statefulActionMessageHash(context);
    expect(mainKey.verifyStatefulRaw(message, signature as StatefulSignature)).toBe(true);
  });

  it("signs at the reserved deploy leaf = quipDeployChainIndex", () => {
    // The stateful signature reveals its leaf as authPath.length.
    const { signature } = buildDeployAuthorization(baseParams({ quipDeployChainIndex: 5 }));
    expect((signature as StatefulSignature).authPath.length).toBe(5);
  });

  it("binds chainId: the same tuple on another chain yields a different context", () => {
    const a = buildDeployContext(baseParams({ chainId: 1 }));
    const b = buildDeployContext(baseParams({ chainId: 10 }));
    expect(a.domainSeparator).not.toBe(b.domainSeparator);
  });

  it("binds the owner: a different owner yields a different payload hash", () => {
    const a = buildDeployContext(baseParams());
    const b = buildDeployContext(
      baseParams({ owner: "0x00000000000000000000000000000000000000b2" as Address })
    );
    expect(a.payloadHash).not.toBe(b.payloadHash);
  });

  it("stateless mode produces a signature without a leaf/authPath", () => {
    const { signature } = buildDeployAuthorization(baseParams({ mode: "stateless" }));
    // Stateless signatures carry no stateful authPath leaf index.
    expect((signature as { authPath?: unknown }).authPath).toBeUndefined();
  });
});
