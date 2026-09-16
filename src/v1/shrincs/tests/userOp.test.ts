// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type Address, type Hex, keccak256, sliceHex, toHex } from "viem";

import { decodeSponsorshipSignature, buildActionContext, domainSeparator, statefulRawMessageHash } from "../shrincsCodec.js";
import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";
import {
  type PackedUserOperation,
  PAYMASTER_DOMAIN_TAG,
  ACTION_PAYMASTER_APPROVE,
  packPaymasterHeader,
  paymasterBindingHash,
  resolveSponsorshipWindow,
  signPaymasterUserOp,
} from "../userOp.js";
import { InvalidSponsorshipWindowError } from "../errors.js";

const PAYMASTER = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" as Address;
const SENDER = "0x00000000000000000000000000000000000A11cE" as Address;
const CHAIN_ID = 31337n;
const MAX_SIG = 8;
// hashsigs-wasm enforces >= 32-byte seeds (ERR_SEED_TOO_SHORT) — hash the label to 32 bytes.
const seed = (s: string) => keccak256(toHex(new TextEncoder().encode(s)));

let verifier: ShrincsKeyPair;

beforeAll(async () => {
  const signer = await ShrincsSigner.create(new TextEncoder().encode("any (hd seed padding)"));
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
      validUntil: 0, // explicit: the unbounded approval the zero header64() encodes
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

    // Blob decodes to the verifier key + a leaf-shaped stateful signature (the
    // sponsorship blob keeps the plain pair layout — no ECDSA co-signer).
    const blob = sliceHex(paymasterAndData, 64);
    const { publicKey, signature } = decodeSponsorshipSignature(blob);
    expect(publicKey).toEqual(verifier.publicKey);
    expect(signature.authPath.length).toBe(leaf);

    // The signature verifies over the canonical sponsorship message. The
    // paymaster context binds nonce 0 (it is outside the wallet's action-nonce
    // scheme) — this doubles as the pin that the sponsorship blob is unchanged
    // by the wallet's nonce redesign.
    const message = verifier.statefulActionMessageHash(
      buildActionContext({
        domainSeparator: domainSeparator(CHAIN_ID, PAYMASTER, PAYMASTER_DOMAIN_TAG),
        nonce: 0n,
        keyVersion: 0n,
        actionType: ACTION_PAYMASTER_APPROVE,
        payloadHash: paymasterBindingHash(op, header64()),
      })
    );
    expect(
      verifier.verifyStatefulRaw(
        statefulRawMessageHash(verifier.publicKeyCommitment, message),
        signature
      )
    ).toBe(true);

    // Deterministic for fixed inputs; different nonce => different signature.
    expect(
      signPaymasterUserOp({
        validUntil: 0, // explicit: the unbounded approval the zero header64() encodes
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
        validUntil: 0, // explicit: the unbounded approval the zero header64() encodes
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

describe("sponsorship validity window", () => {
  const NOW = 1_700_000_000;

  it("defaults validUntil to now + 15 minutes, validAfter to 0", () => {
    expect(resolveSponsorshipWindow({ now: NOW })).toEqual({
      validUntil: NOW + 15 * 60,
      validAfter: 0,
      now: NOW,
    });
  });

  it("packs the default window into the signed header", () => {
    const paymasterAndData = signPaymasterUserOp({
      keypair: verifier,
      userOp: userOpFor(5n, header64()),
      paymaster: PAYMASTER,
      chainId: CHAIN_ID,
      keyVersion: 0n,
      verificationGasLimit: 100_000n,
      postOpGasLimit: 50_000n,
      now: NOW,
      leaf: 3,
    });
    const h = sliceHex(paymasterAndData, 0, 64);
    expect(BigInt(sliceHex(h, 52, 58))).toBe(BigInt(NOW + 15 * 60)); // validUntil
    expect(BigInt(sliceHex(h, 58, 64))).toBe(0n); // validAfter
    // The signature commits to that header: a caller cannot later present the
    // same sponsorship with a different window.
    expect(h).toBe(header64(NOW + 15 * 60, 0));
  });

  it("every timing input is overridable", () => {
    expect(resolveSponsorshipWindow({ now: NOW, validitySeconds: 60 })).toMatchObject({
      validUntil: NOW + 60,
    });
    expect(resolveSponsorshipWindow({ now: NOW, validUntil: NOW + 5, validAfter: NOW + 1 })).toEqual({
      validUntil: NOW + 5,
      validAfter: NOW + 1,
      now: NOW,
    });
    // Wall clock by default.
    const before = Math.floor(Date.now() / 1000);
    const w = resolveSponsorshipWindow({});
    expect(w.now).toBeGreaterThanOrEqual(before);
    expect(w.validUntil).toBe(w.now + 15 * 60);
  });

  it("an unbounded approval is an explicit opt-in (validUntil: 0), never the default", () => {
    expect(resolveSponsorshipWindow({ now: NOW, validUntil: 0 })).toMatchObject({ validUntil: 0 });
    expect(resolveSponsorshipWindow({ now: NOW, validUntil: 0, validAfter: NOW + 100 })).toMatchObject({
      validUntil: 0,
      validAfter: NOW + 100,
    });
  });

  it("rejects malformed windows before a leaf is spent", () => {
    const bad = (p: Parameters<typeof resolveSponsorshipWindow>[0]) =>
      expect(() => resolveSponsorshipWindow({ now: NOW, ...p })).toThrow(InvalidSponsorshipWindowError);
    bad({ validUntil: NOW + 10, validAfter: NOW + 10 }); // inverted / empty
    bad({ validUntil: NOW + 10, validAfter: NOW + 20 });
    bad({ validUntil: NOW }); // already expired at signing time
    bad({ validUntil: NOW - 1 });
    bad({ validUntil: -5 });
    bad({ validAfter: -1 });
    bad({ validUntil: 1.5 });
    bad({ validUntil: 2 ** 48 }); // over the 6-byte field
    bad({ validAfter: 2 ** 48 });
    bad({ validitySeconds: 0 });
    bad({ validitySeconds: -60 });
    // The signing helper surfaces the same error and signs nothing.
    expect(() =>
      signPaymasterUserOp({
        keypair: verifier,
        userOp: userOpFor(5n, header64()),
        paymaster: PAYMASTER,
        chainId: CHAIN_ID,
        keyVersion: 0n,
        now: NOW,
        validUntil: NOW - 1,
        leaf: 4,
      })
    ).toThrow(InvalidSponsorshipWindowError);
  });
});
