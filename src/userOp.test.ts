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
import { describe, it, expect } from "@jest/globals";
import { keccak256, encodeAbiParameters } from "viem";

import { buildUserOp, estimateSponsorshipCost } from "./userOp.js";
import {
  DEFAULT_CALL_GAS_LIMIT,
  DEFAULT_PRE_VERIFICATION_GAS,
  DEFAULT_VERIFICATION_GAS_LIMIT,
} from "./constants.js";
import { CANONICAL_ENTRYPOINT_V07 } from "./addresses.js";
import {
  type PackedUserOperation,
  type WinternitzAddress,
  type WinternitzElements,
  computeUserOpHash,
  encodeUserOpSignature,
  erc4337ExecuteDigest,
  packAccountGasLimits,
  packGasFees,
  packUint128Pair,
  unpackAccountGasLimits,
  unpackGasFees,
} from "./wotsCodec.js";

const WALLET = "0x1111111111111111111111111111111111111111" as const;
const ENTRYPOINT = CANONICAL_ENTRYPOINT_V07;

function makeKey(seed: bigint): WinternitzAddress {
  const toHex32 = (n: bigint) =>
    `0x${n.toString(16).padStart(64, "0")}` as `0x${string}`;
  return {
    publicSeed: toHex32(seed),
    publicKeyHash: toHex32(seed + 1n),
  };
}

function makeSig(seed: bigint): WinternitzElements {
  const toHex32 = (n: bigint) =>
    `0x${n.toString(16).padStart(64, "0")}` as `0x${string}`;
  return {
    elements: Array.from({ length: 67 }, (_, i) => toHex32(seed + 100n + BigInt(i))),
  };
}

describe("packUint128Pair", () => {
  it("packs two zero values to all-zeros bytes32", () => {
    expect(packUint128Pair(0n, 0n)).toBe(
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
  });

  it("packs (1, 1) with hi in upper 16 bytes", () => {
    expect(packUint128Pair(1n, 1n)).toBe(
      "0x0000000000000000000000000000000100000000000000000000000000000001"
    );
  });

  it("packs (2^128 - 1, 0) into upper half only", () => {
    expect(packUint128Pair((1n << 128n) - 1n, 0n)).toBe(
      "0xffffffffffffffffffffffffffffffff00000000000000000000000000000000"
    );
  });

  it("rejects values >= 2^128", () => {
    expect(() => packUint128Pair(1n << 128n, 0n)).toThrow();
    expect(() => packUint128Pair(0n, 1n << 128n)).toThrow();
  });

  it("rejects negative values", () => {
    expect(() => packUint128Pair(-1n, 0n)).toThrow();
    expect(() => packUint128Pair(0n, -1n)).toThrow();
  });
});

describe("packAccountGasLimits / unpackAccountGasLimits round-trip", () => {
  it("round-trips representative values", () => {
    const v = 1_234_567n;
    const c = 9_876_543n;
    const packed = packAccountGasLimits(v, c);
    const out = unpackAccountGasLimits(packed);
    expect(out.verificationGasLimit).toBe(v);
    expect(out.callGasLimit).toBe(c);
  });

  it("round-trips uint128 maxima", () => {
    const m = (1n << 128n) - 1n;
    const packed = packAccountGasLimits(m, m);
    const out = unpackAccountGasLimits(packed);
    expect(out.verificationGasLimit).toBe(m);
    expect(out.callGasLimit).toBe(m);
  });
});

describe("packGasFees / unpackGasFees round-trip", () => {
  it("round-trips representative values", () => {
    const prio = 2n * 10n ** 9n;
    const max = 50n * 10n ** 9n;
    const packed = packGasFees(prio, max);
    const out = unpackGasFees(packed);
    expect(out.maxPriorityFeePerGas).toBe(prio);
    expect(out.maxFeePerGas).toBe(max);
  });
});

describe("buildUserOp", () => {
  it("fills defaults when gas budgets are omitted", () => {
    const userOp = buildUserOp({
      sender: WALLET,
      nonce: 7n,
      callData: "0xdead",
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 2n,
    });
    const { verificationGasLimit, callGasLimit } = unpackAccountGasLimits(
      userOp.accountGasLimits
    );
    expect(verificationGasLimit).toBe(DEFAULT_VERIFICATION_GAS_LIMIT);
    expect(callGasLimit).toBe(DEFAULT_CALL_GAS_LIMIT);
    expect(userOp.preVerificationGas).toBe(DEFAULT_PRE_VERIFICATION_GAS);
    expect(userOp.initCode).toBe("0x");
    expect(userOp.paymasterAndData).toBe("0x");
    expect(userOp.signature).toBe("0x");
  });

  it("honors explicit gas + fee fields", () => {
    const userOp = buildUserOp({
      sender: WALLET,
      nonce: 0n,
      callData: "0x",
      verificationGasLimit: 100n,
      callGasLimit: 200n,
      preVerificationGas: 300n,
      maxPriorityFeePerGas: 400n,
      maxFeePerGas: 500n,
    });
    const acg = unpackAccountGasLimits(userOp.accountGasLimits);
    const gf = unpackGasFees(userOp.gasFees);
    expect(acg.verificationGasLimit).toBe(100n);
    expect(acg.callGasLimit).toBe(200n);
    expect(userOp.preVerificationGas).toBe(300n);
    expect(gf.maxPriorityFeePerGas).toBe(400n);
    expect(gf.maxFeePerGas).toBe(500n);
  });
});

describe("estimateSponsorshipCost", () => {
  // Build a userOp with known gas-limit and fee fields, optionally with a
  // paymaster-andData prefix.
  function userOpWith(params: {
    verificationGasLimit: bigint;
    callGasLimit: bigint;
    preVerificationGas: bigint;
    maxPriorityFeePerGas: bigint;
    maxFeePerGas: bigint;
    paymasterAndData?: `0x${string}`;
  }): PackedUserOperation {
    const userOp = buildUserOp({
      sender: WALLET,
      nonce: 0n,
      callData: "0x",
      verificationGasLimit: params.verificationGasLimit,
      callGasLimit: params.callGasLimit,
      preVerificationGas: params.preVerificationGas,
      maxPriorityFeePerGas: params.maxPriorityFeePerGas,
      maxFeePerGas: params.maxFeePerGas,
    });
    return {
      ...userOp,
      paymasterAndData: params.paymasterAndData ?? "0x",
    };
  }

  // EP v0.7 paymasterAndData header: address(20) + verifGasLimit(16) + postOpGasLimit(16) = 52 bytes
  function pmdHeader(
    paymaster: `0x${string}`,
    verifGasLimit: bigint,
    postOpGasLimit: bigint
  ): `0x${string}` {
    const v = verifGasLimit.toString(16).padStart(32, "0");
    const p = postOpGasLimit.toString(16).padStart(32, "0");
    return `${paymaster}${v}${p}` as `0x${string}`;
  }

  it("self-sponsored userOp: paymaster gas limits are zero", () => {
    const userOp = userOpWith({
      verificationGasLimit: 100_000n,
      callGasLimit: 200_000n,
      preVerificationGas: 50_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      maxFeePerGas: 5_000_000_000n,
    });
    const out = estimateSponsorshipCost(userOp);
    expect(out.verificationGasLimit).toBe(100_000n);
    expect(out.callGasLimit).toBe(200_000n);
    expect(out.preVerificationGas).toBe(50_000n);
    expect(out.paymasterVerificationGasLimit).toBe(0n);
    expect(out.paymasterPostOpGasLimit).toBe(0n);
    expect(out.maxPriorityFeePerGas).toBe(1_000_000_000n);
    expect(out.maxFeePerGas).toBe(5_000_000_000n);
    expect(out.totalGasLimit).toBe(350_000n);
    expect(out.maxCost).toBe(350_000n * 5_000_000_000n);
  });

  it("sponsored userOp: includes paymaster verification + postOp gas", () => {
    const userOp = userOpWith({
      verificationGasLimit: 100_000n,
      callGasLimit: 200_000n,
      preVerificationGas: 50_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      maxFeePerGas: 5_000_000_000n,
      paymasterAndData: pmdHeader(
        "0x2222222222222222222222222222222222222222",
        80_000n,
        30_000n
      ),
    });
    const out = estimateSponsorshipCost(userOp);
    expect(out.paymasterVerificationGasLimit).toBe(80_000n);
    expect(out.paymasterPostOpGasLimit).toBe(30_000n);
    expect(out.totalGasLimit).toBe(100_000n + 200_000n + 50_000n + 80_000n + 30_000n);
    expect(out.maxCost).toBe(out.totalGasLimit * 5_000_000_000n);
  });

  it("matches the EP v0.7 requiredPrefund formula exactly", () => {
    // Explicit values picked to make the arithmetic checkable by hand:
    //   gas = 7 + 11 + 13 + 17 + 19 = 67
    //   maxFeePerGas = 1e9
    //   maxCost = 67e9
    const userOp = userOpWith({
      verificationGasLimit: 7n,
      callGasLimit: 11n,
      preVerificationGas: 13n,
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 1_000_000_000n,
      paymasterAndData: pmdHeader(
        "0x3333333333333333333333333333333333333333",
        17n,
        19n
      ),
    });
    const out = estimateSponsorshipCost(userOp);
    expect(out.totalGasLimit).toBe(67n);
    expect(out.maxCost).toBe(67n * 1_000_000_000n);
  });

  it("ignores trailing paymaster-specific data after the 52-byte header", () => {
    // Real paymasterAndData includes validUntil/validAfter/verifier/sig
    // after the standardized header. estimateSponsorshipCost must only
    // consume the first 52 bytes.
    const userOp = userOpWith({
      verificationGasLimit: 100n,
      callGasLimit: 200n,
      preVerificationGas: 300n,
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 10n,
      paymasterAndData: (pmdHeader(
        "0x4444444444444444444444444444444444444444",
        400n,
        500n
      ) + "deadbeef".repeat(32)) as `0x${string}`, // junk trailing data
    });
    const out = estimateSponsorshipCost(userOp);
    expect(out.paymasterVerificationGasLimit).toBe(400n);
    expect(out.paymasterPostOpGasLimit).toBe(500n);
    expect(out.maxCost).toBe(1500n * 10n);
  });

  it("throws on malformed paymasterAndData (1..51 bytes)", () => {
    const userOp = userOpWith({
      verificationGasLimit: 1n,
      callGasLimit: 1n,
      preVerificationGas: 1n,
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 1n,
      // 20-byte address only — missing the gas-limit fields.
      paymasterAndData: "0x5555555555555555555555555555555555555555",
    });
    expect(() => estimateSponsorshipCost(userOp)).toThrow(
      /paymasterAndData length 20/
    );
  });

  it("zero fees produce zero maxCost", () => {
    const userOp = userOpWith({
      verificationGasLimit: 100n,
      callGasLimit: 200n,
      preVerificationGas: 50n,
      maxPriorityFeePerGas: 0n,
      maxFeePerGas: 0n,
    });
    const out = estimateSponsorshipCost(userOp);
    expect(out.totalGasLimit).toBe(350n);
    expect(out.maxCost).toBe(0n);
  });
});

describe("computeUserOpHash (v0.7 reference parity)", () => {
  // The v0.7 hash formula is:
  //   keccak256(abi.encode(hashUserOp(userOp), entryPoint, chainId))
  // where hashUserOp pre-hashes the bytes fields.
  // This test verifies our implementation matches the formula at the
  // bytecode-level — exact parity against a deployed EntryPoint is
  // covered by the Anvil integration test (state-overridden EntryPoint
  // bytecode + getUserOpHash readback).

  it("matches a hand-computed digest for a fixed UserOp", () => {
    const userOp: PackedUserOperation = {
      sender: WALLET,
      nonce: 42n,
      initCode: "0x",
      callData: "0xabcd",
      accountGasLimits: packAccountGasLimits(1_000_000n, 500_000n),
      preVerificationGas: 80_000n,
      gasFees: packGasFees(1n * 10n ** 9n, 20n * 10n ** 9n),
      paymasterAndData: "0x",
      signature: "0x",
    };

    const inner = keccak256(
      encodeAbiParameters(
        [
          { type: "address" },
          { type: "uint256" },
          { type: "bytes32" },
          { type: "bytes32" },
          { type: "bytes32" },
          { type: "uint256" },
          { type: "bytes32" },
          { type: "bytes32" },
        ],
        [
          userOp.sender,
          userOp.nonce,
          keccak256(userOp.initCode),
          keccak256(userOp.callData),
          userOp.accountGasLimits,
          userOp.preVerificationGas,
          userOp.gasFees,
          keccak256(userOp.paymasterAndData),
        ]
      )
    );
    const expected = keccak256(
      encodeAbiParameters(
        [{ type: "bytes32" }, { type: "address" }, { type: "uint256" }],
        [inner, ENTRYPOINT, 1n]
      )
    );

    expect(computeUserOpHash(userOp, ENTRYPOINT, 1n)).toBe(expected);
  });

  it("hash changes when any field changes (signature excluded)", () => {
    const base: PackedUserOperation = {
      sender: WALLET,
      nonce: 0n,
      initCode: "0x",
      callData: "0x",
      accountGasLimits: packAccountGasLimits(0n, 0n),
      preVerificationGas: 0n,
      gasFees: packGasFees(0n, 0n),
      paymasterAndData: "0x",
      signature: "0x",
    };
    const baseHash = computeUserOpHash(base, ENTRYPOINT, 1n);

    // Each mutation should change the hash...
    const nonceChange = computeUserOpHash(
      { ...base, nonce: 1n },
      ENTRYPOINT,
      1n
    );
    expect(nonceChange).not.toBe(baseHash);

    const callDataChange = computeUserOpHash(
      { ...base, callData: "0xff" },
      ENTRYPOINT,
      1n
    );
    expect(callDataChange).not.toBe(baseHash);

    // ...except the signature field, which is excluded from the hash.
    const sigChange = computeUserOpHash(
      { ...base, signature: "0xdeadbeef" },
      ENTRYPOINT,
      1n
    );
    expect(sigChange).toBe(baseHash);
  });

  it("hash changes with entryPoint and chainId", () => {
    const userOp: PackedUserOperation = {
      sender: WALLET,
      nonce: 0n,
      initCode: "0x",
      callData: "0x",
      accountGasLimits: packAccountGasLimits(0n, 0n),
      preVerificationGas: 0n,
      gasFees: packGasFees(0n, 0n),
      paymasterAndData: "0x",
      signature: "0x",
    };
    const a = computeUserOpHash(userOp, ENTRYPOINT, 1n);
    const b = computeUserOpHash(userOp, ENTRYPOINT, 8453n);
    expect(a).not.toBe(b);

    const otherEp = "0x0000000000000000000000000000000000000099" as const;
    const c = computeUserOpHash(userOp, otherEp, 1n);
    expect(a).not.toBe(c);
  });
});

describe("erc4337ExecuteDigest (wallet UserOp digest)", () => {
  it("produces a different digest per (currentKey, nextKey, fee)", () => {
    const userOp: PackedUserOperation = {
      sender: WALLET,
      nonce: 0n,
      initCode: "0x",
      callData: "0x",
      accountGasLimits: packAccountGasLimits(0n, 0n),
      preVerificationGas: 0n,
      gasFees: packGasFees(0n, 0n),
      paymasterAndData: "0x",
      signature: "0x",
    };
    const userOpHash = computeUserOpHash(userOp, ENTRYPOINT, 1n);

    const ck = makeKey(1n);
    const nk = makeKey(2n);
    const base = erc4337ExecuteDigest(
      WALLET,
      1n,
      ck.publicSeed,
      ck.publicKeyHash,
      nk.publicSeed,
      nk.publicKeyHash,
      userOpHash,
      0n
    );

    const feeChange = erc4337ExecuteDigest(
      WALLET,
      1n,
      ck.publicSeed,
      ck.publicKeyHash,
      nk.publicSeed,
      nk.publicKeyHash,
      userOpHash,
      1n
    );
    expect(feeChange).not.toBe(base);

    const otherNext = makeKey(3n);
    const keyChange = erc4337ExecuteDigest(
      WALLET,
      1n,
      ck.publicSeed,
      ck.publicKeyHash,
      otherNext.publicSeed,
      otherNext.publicKeyHash,
      userOpHash,
      0n
    );
    expect(keyChange).not.toBe(base);
  });
});

describe("encodeUserOpSignature (wallet signature payload)", () => {
  it("produces 2272 bytes (64 + 64 + 67*32)", () => {
    const sig = encodeUserOpSignature(makeKey(1n), makeKey(2n), makeSig(3n));
    // 0x prefix + 2272 * 2 hex chars
    expect(sig.length).toBe(2 + 2272 * 2);
  });

  it("places currentKey/nextKey in the first 128 bytes", () => {
    const ck = makeKey(0x10n);
    const nk = makeKey(0x20n);
    const sig = encodeUserOpSignature(ck, nk, makeSig(0xffn));
    expect(sig.slice(2, 2 + 64)).toBe(ck.publicSeed.slice(2));
    expect(sig.slice(2 + 64, 2 + 128)).toBe(ck.publicKeyHash.slice(2));
    expect(sig.slice(2 + 128, 2 + 192)).toBe(nk.publicSeed.slice(2));
    expect(sig.slice(2 + 192, 2 + 256)).toBe(nk.publicKeyHash.slice(2));
  });
});
