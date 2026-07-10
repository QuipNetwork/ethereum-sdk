// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type Address, type Hex, sliceHex, toHex } from "viem";

import { decodeUserOpSignature, buildActionContext, domainSeparator } from "../shrincsCodec.js";
import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";
import {
  type PackedUserOperation,
  PAYMASTER_DOMAIN_TAG,
  ACTION_PAYMASTER_APPROVE,
  packPaymasterHeader,
  paymasterBindingHash,
  signPaymasterUserOp,
} from "../userOp.js";

const PAYMASTER = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" as Address;
const SENDER = "0x00000000000000000000000000000000000A11cE" as Address;
const CHAIN_ID = 31337n;
const MAX_SIG = 8;
const seed = (s: string) => toHex(new TextEncoder().encode(s));

let verifier: ShrincsKeyPair;

beforeAll(async () => {
  const signer = await ShrincsSigner.create(new TextEncoder().encode("any"));
  verifier = signer.keygenFromSeedHex(seed("shrincs paymaster verifier seed"), {
    maxSignatures: MAX_SIG,
  });
});

function header64(validUntil = 0, validAfter = 0): Hex {
  return packPaymasterHeader({
    paymaster: PAYMASTER,
    verificationGasLimit: 100_000n,
    postOpGasLimit: 50_000n,
    validUntil,
    validAfter,
  });
}

function userOpFor(nonce: bigint, paymasterAndData: Hex): PackedUserOperation {
  return {
    sender: SENDER,
    nonce,
    initCode: "0x",
    callData: "0x",
    accountGasLimits: toHex((100_000n << 128n) | 100_000n, { size: 32 }),
    preVerificationGas: 21_000n,
    gasFees: toHex((1_000_000_000n << 128n) | 10_000_000_000n, { size: 32 }),
    paymasterAndData,
    signature: "0x",
  };
}

describe("shrincs paymaster userOp", () => {
  it("packPaymasterHeader lays out the 64-byte prefix", () => {
    const h = header64(7, 3);
    expect((h.length - 2) / 2).toBe(64);
    expect(sliceHex(h, 0, 20).toLowerCase()).toBe(PAYMASTER.toLowerCase());
    expect(BigInt(sliceHex(h, 20, 36))).toBe(100_000n); // verificationGasLimit
    expect(BigInt(sliceHex(h, 36, 52))).toBe(50_000n); // postOpGasLimit
    expect(BigInt(sliceHex(h, 52, 58))).toBe(7n); // validUntil
    expect(BigInt(sliceHex(h, 58, 64))).toBe(3n); // validAfter
  });

  it("binding hash binds the op fields and header — and ONLY the 64-byte prefix", () => {
    const h = header64();
    const base = paymasterBindingHash(userOpFor(0n, h), h);
    // Deterministic; sensitive to nonce, sender-carried fields, and the header.
    expect(paymasterBindingHash(userOpFor(0n, h), h)).toBe(base);
    expect(paymasterBindingHash(userOpFor(1n, h), h)).not.toBe(base);
    expect(paymasterBindingHash(userOpFor(0n, h), header64(1, 0))).not.toBe(base);
    // The blob appended past the prefix is deliberately NOT bound: the binding
    // is computed from the header alone, so an op carrying any blob at [64:)
    // has the same binding hash (this is the circularity break).
    const withBlob = userOpFor(0n, (h + "deadbeef") as Hex);
    expect(paymasterBindingHash(withBlob, h)).toBe(base);
  });

  it("signPaymasterUserOp emits header ‖ blob that verifies against the canonical context", () => {
    const leaf = 2;
    const op = userOpFor(5n, header64());
    const paymasterAndData = signPaymasterUserOp({
      keypair: verifier,
      userOp: op,
      paymaster: PAYMASTER,
      chainId: CHAIN_ID,
      keyVersion: 0n,
      verificationGasLimit: 100_000n,
      postOpGasLimit: 50_000n,
      leaf,
    });

    // Prefix is the exact signed header.
    expect(sliceHex(paymasterAndData, 0, 64)).toBe(header64());

    // Blob decodes to the verifier key + a leaf-shaped stateful signature.
    const blob = sliceHex(paymasterAndData, 64);
    const { publicKey, signature } = decodeUserOpSignature(blob);
    expect(publicKey).toEqual(verifier.publicKey);
    expect(signature.authPath.length).toBe(leaf);

    // The signature verifies over the canonical sponsorship message.
    const message = verifier.statefulActionMessageHash(
      buildActionContext({
        domainSeparator: domainSeparator(CHAIN_ID, PAYMASTER, PAYMASTER_DOMAIN_TAG),
        keyVersion: 0n,
        actionType: ACTION_PAYMASTER_APPROVE,
        payloadHash: paymasterBindingHash(op, header64()),
      })
    );
    expect(verifier.verifyStatefulRaw(message, signature)).toBe(true);

    // Deterministic for fixed inputs; different nonce => different signature.
    expect(
      signPaymasterUserOp({
        keypair: verifier,
        userOp: op,
        paymaster: PAYMASTER,
        chainId: CHAIN_ID,
        keyVersion: 0n,
        verificationGasLimit: 100_000n,
        postOpGasLimit: 50_000n,
        leaf,
      })
    ).toBe(paymasterAndData);
    expect(
      signPaymasterUserOp({
        keypair: verifier,
        userOp: userOpFor(6n, header64()),
        paymaster: PAYMASTER,
        chainId: CHAIN_ID,
        keyVersion: 0n,
        verificationGasLimit: 100_000n,
        postOpGasLimit: 50_000n,
        leaf,
      })
    ).not.toBe(paymasterAndData);
  });
});
