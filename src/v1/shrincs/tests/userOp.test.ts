// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { type Hex, toHex } from "viem";

import { ShrincsSigner } from "../shrincsSigner.js";
import {
  type PackedUserOperation,
  PAYMASTER_DOMAIN_TAG,
  ACTION_PAYMASTER_APPROVE,
  packPaymasterHeader,
  paymasterBindingHash,
} from "../userOp.js";
import { buildActionContext, domainSeparator } from "../shrincsCodec.js";

const v = JSON.parse(
  readFileSync(
    resolve(process.cwd(), "test/test_vectors/shrincs_paymaster_sphincs_256s_keccak.json"),
    "utf8"
  )
) as any;

const seed = (s: string) => toHex(new TextEncoder().encode(s));

function header64(): Hex {
  return packPaymasterHeader({
    paymaster: v.paymaster,
    verificationGasLimit: BigInt(v.userOp.verificationGasLimit),
    postOpGasLimit: BigInt(v.userOp.postOpGasLimit),
    validUntil: v.userOp.validUntil,
    validAfter: v.userOp.validAfter,
  });
}

function userOpFor(nonce: number, paymasterAndData: Hex): PackedUserOperation {
  return {
    sender: v.userOp.sender,
    nonce: BigInt(nonce),
    initCode: v.userOp.initCode,
    callData: v.userOp.callData,
    accountGasLimits: v.userOp.accountGasLimits,
    preVerificationGas: BigInt(v.userOp.preVerificationGas),
    gasFees: v.userOp.gasFees,
    paymasterAndData,
    signature: "0x",
  };
}

describe("shrincs paymaster userOp", () => {
  it("reproduces the sponsorship binding hash for each sponsor case", () => {
    const h = header64();
    for (const idx of Object.keys(v.cases.sponsor)) {
      const c = v.cases.sponsor[idx];
      const userOp = userOpFor(c.nonce, h);
      expect(paymasterBindingHash(userOp, h)).toBe(c.bindingHash);
    }
  });

  it("reproduces the canonical message and signature at the pinned leaf", async () => {
    const signer = await ShrincsSigner.create(new TextEncoder().encode("any"));
    const verifier = signer.keygenFromSeedHex(seed("shrincs paymaster verifier seed"), {
      maxSignatures: 8,
    });
    expect(verifier.publicKeyCommitment).toBe(v.verifierKey.publicKeyCommitment);

    const h = header64();
    for (const idx of Object.keys(v.cases.sponsor)) {
      const c = v.cases.sponsor[idx];
      const userOp = userOpFor(c.nonce, h);
      const ctx = buildActionContext({
        domainSeparator: domainSeparator(v.chainId, v.paymaster, PAYMASTER_DOMAIN_TAG),
        keyVersion: BigInt(c.keyVersion),
        actionType: ACTION_PAYMASTER_APPROVE,
        payloadHash: paymasterBindingHash(userOp, h),
      });
      expect(verifier.statefulActionMessageHash(ctx)).toBe(c.message);
      expect(verifier.signStatefulRawAt(c.message, c.leaf)).toEqual(c.signature);
    }
  });
});
