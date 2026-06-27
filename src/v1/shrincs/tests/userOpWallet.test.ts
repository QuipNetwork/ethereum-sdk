// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  type Address,
  type Hex,
  decodeFunctionData,
  encodeFunctionData,
  getAddress,
  toHex,
} from "viem";

import { shrincsWalletAbi } from "../abi/ShrincsWallet.js";
import {
  DEFAULT_CALL_GAS_LIMIT,
  DEFAULT_PRE_VERIFICATION_GAS,
  DEFAULT_VERIFICATION_GAS_LIMIT,
} from "../constants.js";
import {
  ACTION_ERC4337_EXECUTE,
  buildActionContext,
  decodeUserOpSignature,
  domainSeparator,
  erc4337PayloadHash,
} from "../shrincsCodec.js";
import { ShrincsSigner } from "../shrincsSigner.js";
import {
  type PackedUserOperation,
  buildUserOp,
  signWalletUserOp,
} from "../userOp.js";
import {
  computeUserOpHash,
  packAccountGasLimits,
  packGasFees,
} from "../../wotsCodec.js";

const vectors = JSON.parse(
  readFileSync(
    resolve(process.cwd(), "test/test_vectors/shrincs_wallet_sphincs_256s_keccak.json"),
    "utf8"
  )
) as any;

const WALLET = vectors.wallet as Address;
const CHAIN_ID = BigInt(vectors.chainId);
const ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032" as const;
const MAX_SIG = 8;
const seed = (s: string) => toHex(new TextEncoder().encode(s));

const TARGET = "0x00000000000000000000000000000000000000b0" as Address;
const SENDER = WALLET;

describe("shrincs wallet userOp", () => {
  describe("buildUserOp", () => {
    it("applies gas defaults and leaves signature '0x'", () => {
      const op = buildUserOp({
        sender: SENDER,
        nonce: 0n,
        callData: "0xdeadbeef",
        maxFeePerGas: 100n,
        maxPriorityFeePerGas: 1n,
      });
      expect(op.sender).toBe(SENDER);
      expect(op.nonce).toBe(0n);
      expect(op.initCode).toBe("0x");
      expect(op.callData).toBe("0xdeadbeef");
      expect(op.paymasterAndData).toBe("0x");
      expect(op.signature).toBe("0x");
      expect(op.accountGasLimits).toBe(
        packAccountGasLimits(DEFAULT_VERIFICATION_GAS_LIMIT, DEFAULT_CALL_GAS_LIMIT)
      );
      expect(op.preVerificationGas).toBe(DEFAULT_PRE_VERIFICATION_GAS);
      expect(op.gasFees).toBe(packGasFees(1n, 100n));
    });

    it("passes through explicit gas + initCode + paymasterAndData overrides", () => {
      const op = buildUserOp({
        sender: SENDER,
        nonce: 7n,
        callData: "0x01",
        initCode: "0xabcd",
        verificationGasLimit: 11n,
        callGasLimit: 22n,
        preVerificationGas: 33n,
        maxFeePerGas: 44n,
        maxPriorityFeePerGas: 55n,
        paymasterAndData: "0xbeef",
      });
      expect(op.nonce).toBe(7n);
      expect(op.initCode).toBe("0xabcd");
      expect(op.paymasterAndData).toBe("0xbeef");
      expect(op.accountGasLimits).toBe(packAccountGasLimits(11n, 22n));
      expect(op.preVerificationGas).toBe(33n);
      expect(op.gasFees).toBe(packGasFees(55n, 44n));
    });
  });

  describe("callData encoding (execute / executeBatch)", () => {
    it("execute(target,value,data) round-trips via decodeFunctionData", () => {
      const data = "0xa9059cbb" as Hex;
      const callData = encodeFunctionData({
        abi: shrincsWalletAbi,
        functionName: "execute",
        args: [TARGET, 1_000_000_000n, data],
      });
      const decoded = decodeFunctionData({ abi: shrincsWalletAbi, data: callData });
      expect(decoded.functionName).toBe("execute");
      // viem decodes addresses to EIP-55 checksum form, so normalize before compare.
      expect(decoded.args).toEqual([getAddress(TARGET), 1_000_000_000n, data]);
    });

    it("executeBatch(Call[]) round-trips the 3-tuple call list", () => {
      const calls = [
        { target: TARGET, value: 0n, data: "0x" as Hex },
        { target: SENDER, value: 5n, data: "0x1234" as Hex },
      ];
      const callData = encodeFunctionData({
        abi: shrincsWalletAbi,
        functionName: "executeBatch",
        args: [calls],
      });
      const decoded = decodeFunctionData({ abi: shrincsWalletAbi, data: callData });
      expect(decoded.functionName).toBe("executeBatch");
      const expected = calls.map((c) => ({ ...c, target: getAddress(c.target) }));
      expect(decoded.args).toEqual([expected]);
    });
  });

  describe("signWalletUserOp", () => {
    function userOp(callData: Hex): PackedUserOperation {
      return buildUserOp({
        sender: SENDER,
        nonce: 0n,
        callData,
        maxFeePerGas: 100n,
        maxPriorityFeePerGas: 1n,
      });
    }

    it("returns a signature that decodes back to the signing key, with a consistent userOpHash", async () => {
      const signer = await ShrincsSigner.create(new TextEncoder().encode("any master"));
      const main = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
        maxSignatures: MAX_SIG,
      });
      // Sanity: this is the committed wallet main key.
      expect(main.publicKeyCommitment).toBe(vectors.mainKey.publicKeyCommitment);

      const callData = encodeFunctionData({
        abi: shrincsWalletAbi,
        functionName: "execute",
        args: [TARGET, 0n, "0x" as Hex],
      });
      const op = userOp(callData);

      const { signature, userOpHash } = signWalletUserOp({
        keypair: main,
        userOp: op,
        entryPoint: ENTRY_POINT,
        chainId: CHAIN_ID,
        wallet: WALLET,
        executeFee: 0n,
        keyVersion: 0n,
        leaf: 1,
      });

      // userOpHash matches the canonical ERC-4337 v0.7 hash.
      expect(userOpHash).toBe(computeUserOpHash(op, ENTRY_POINT, CHAIN_ID));

      // The signature blob decodes back to the signing key's public bundle.
      const decoded = decodeUserOpSignature(signature);
      expect(decoded.publicKey).toEqual(main.publicKey);
      // authPath length equals the signing leaf (stateful invariant).
      expect(decoded.signature.authPath.length).toBe(1);
      // And the embedded signature verifies against the canonical action message
      // (domainSeparator ‖ erc4337 action ‖ erc4337PayloadHash(userOpHash, fee)).
      const message = main.statefulActionMessageHash(
        buildActionContext({
          domainSeparator: domainSeparator(CHAIN_ID, WALLET),
          keyVersion: 0n,
          actionType: ACTION_ERC4337_EXECUTE,
          payloadHash: erc4337PayloadHash(userOpHash, 0n),
        })
      );
      expect(main.verifyStatefulRaw(message, decoded.signature)).toBe(true);
    });

    it("is deterministic for a fixed (userOp, leaf, keyVersion)", async () => {
      const signer = await ShrincsSigner.create(new TextEncoder().encode("any master"));
      const main = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
        maxSignatures: MAX_SIG,
      });
      const op = userOp("0x1234" as Hex);
      const args = {
        keypair: main,
        userOp: op,
        entryPoint: ENTRY_POINT,
        chainId: CHAIN_ID,
        wallet: WALLET,
        executeFee: 0n,
        keyVersion: 0n,
        leaf: 2,
      };
      const a = signWalletUserOp(args);
      const b = signWalletUserOp(args);
      expect(a.signature).toBe(b.signature);
      expect(a.userOpHash).toBe(b.userOpHash);
    });

    it("binds the wallet domain separator (different wallet => different signature)", async () => {
      const signer = await ShrincsSigner.create(new TextEncoder().encode("any master"));
      const main = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
        maxSignatures: MAX_SIG,
      });
      const op = userOp("0x" as Hex);
      const base = {
        keypair: main,
        userOp: op,
        entryPoint: ENTRY_POINT,
        chainId: CHAIN_ID,
        executeFee: 0n,
        keyVersion: 0n,
        leaf: 3,
      };
      const a = signWalletUserOp({ ...base, wallet: WALLET });
      const b = signWalletUserOp({
        ...base,
        wallet: "0x000000000000000000000000000000000000dEaD",
      });
      // Same userOp => same userOpHash, but the signed message is domain-bound.
      expect(a.userOpHash).toBe(b.userOpHash);
      expect(a.signature).not.toBe(b.signature);
      // Confirm the domain separators actually differ (sanity for the binding).
      expect(domainSeparator(CHAIN_ID, WALLET)).not.toBe(
        domainSeparator(CHAIN_ID, "0x000000000000000000000000000000000000dEaD")
      );
    });
  });
});
