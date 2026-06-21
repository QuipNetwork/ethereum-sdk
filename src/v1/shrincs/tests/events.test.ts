// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Abi,
  type AbiEvent,
  type Hex,
  type Log,
  encodeAbiParameters,
  encodeEventTopics,
  getAbiItem,
  pad,
} from "viem";

import { shrincsWalletAbi } from "../abi/ShrincsWallet.js";
import { shrincsPaymasterAbi } from "../abi/ShrincsPaymaster.js";
import {
  PaymasterValidationFailure,
  UserOpValidationFailure,
} from "../errors.js";
import {
  parseErc1271KeySet,
  parseExecutionSucceeded,
  parseKeyRotated,
  parseLeafConsumedOnly,
  parsePaymasterInitialized,
  parsePaymasterValidationRejected,
  parseShrincsVerifierSet,
  parseSponsorshipVerified,
  parseStatefulSignatureVerified,
  parseUserOpSponsored,
  parseUserOpValidationRejected,
  parseWalletInitialized,
  parseWalletMigrated,
} from "../events.js";

const ADDR_A = "0x1111111111111111111111111111111111111111" as const;
const ADDR_B = "0x2222222222222222222222222222222222222222" as const;
const ADDR_C = "0x3333333333333333333333333333333333333333" as const;
const B32 = (b: number): Hex => pad(`0x${b.toString(16).padStart(2, "0")}`, { size: 32 });

/// Synthesize a `Log` for `eventName`: topics from `encodeEventTopics` (indexed
/// args), data from `encodeAbiParameters` over the non-indexed params. Returns a
/// fully-shaped `Log` the parsers can consume via a `readonly Log[]`.
function makeLog(
  abi: Abi,
  address: Hex,
  eventName: string,
  args: Record<string, unknown>
): Log {
  const ev = getAbiItem({ abi, name: eventName }) as AbiEvent;
  const topics = encodeEventTopics({
    abi,
    eventName,
    args: args as never,
  } as never);

  const dataParams = ev.inputs.filter((i) => !i.indexed);
  const dataValues = dataParams.map((p) => args[p.name as string]);
  const data =
    dataParams.length > 0
      ? encodeAbiParameters(dataParams, dataValues as never)
      : "0x";

  return {
    address: address as `0x${string}`,
    topics: topics as [Hex, ...Hex[]],
    data,
    blockHash: B32(0xbb),
    blockNumber: 1n,
    logIndex: 0,
    transactionHash: B32(0xaa),
    transactionIndex: 0,
    removed: false,
  } as Log;
}

describe("shrincs event parsers", () => {
  describe("wallet events", () => {
    it("parseWalletInitialized", () => {
      const log = makeLog(shrincsWalletAbi as Abi, ADDR_A, "WalletInitialized", {
        factory: ADDR_B,
        owner: ADDR_C,
        shrincsPublicKeyCommitment: B32(0x11),
        erc1271StatelessCommitment: B32(0x22),
      });
      expect(parseWalletInitialized([log])).toEqual([
        {
          factory: ADDR_B,
          owner: ADDR_C,
          shrincsPublicKeyCommitment: B32(0x11),
          erc1271StatelessCommitment: B32(0x22),
        },
      ]);
    });

    it("parseStatefulSignatureVerified coerces leaf->number, keyVersion->bigint", () => {
      const log = makeLog(
        shrincsWalletAbi as Abi,
        ADDR_A,
        "StatefulSignatureVerified",
        { leaf: 5, keyVersion: 9n }
      );
      const [out] = parseStatefulSignatureVerified([log]);
      expect(out).toEqual({ leaf: 5, keyVersion: 9n });
      expect(typeof out.leaf).toBe("number");
      expect(typeof out.keyVersion).toBe("bigint");
    });

    it("parseLeafConsumedOnly", () => {
      const log = makeLog(shrincsWalletAbi as Abi, ADDR_A, "LeafConsumedOnly", {
        leaf: 3,
      });
      const [out] = parseLeafConsumedOnly([log]);
      expect(out).toEqual({ leaf: 3 });
      expect(typeof out.leaf).toBe("number");
    });

    it("parseExecutionSucceeded", () => {
      const log = makeLog(shrincsWalletAbi as Abi, ADDR_A, "ExecutionSucceeded", {
        target: ADDR_B,
        value: 1_000n,
        dataHash: B32(0x44),
      });
      expect(parseExecutionSucceeded([log])).toEqual([
        { target: ADDR_B, value: 1_000n, dataHash: B32(0x44) },
      ]);
    });

    it("parseErc1271KeySet", () => {
      const log = makeLog(shrincsWalletAbi as Abi, ADDR_A, "Erc1271KeySet", {
        oldCommitment: B32(0x10),
        newCommitment: B32(0x20),
      });
      expect(parseErc1271KeySet([log])).toEqual([
        { oldCommitment: B32(0x10), newCommitment: B32(0x20) },
      ]);
    });

    it("parseKeyRotated", () => {
      const log = makeLog(shrincsWalletAbi as Abi, ADDR_A, "KeyRotated", {
        previousCommitment: B32(0x30),
        nextCommitment: B32(0x40),
        parameterSetId: 0,
        keyVersion: 7n,
      });
      const [out] = parseKeyRotated([log]);
      expect(out).toEqual({
        previousCommitment: B32(0x30),
        nextCommitment: B32(0x40),
        parameterSetId: 0,
        keyVersion: 7n,
      });
      expect(typeof out.parameterSetId).toBe("number");
      expect(typeof out.keyVersion).toBe("bigint");
    });

    it("parseWalletMigrated", () => {
      const log = makeLog(shrincsWalletAbi as Abi, ADDR_A, "WalletMigrated", {
        shrincsPublicKeyCommitment: B32(0x55),
        keyVersion: 2n,
      });
      const [out] = parseWalletMigrated([log]);
      expect(out).toEqual({
        shrincsPublicKeyCommitment: B32(0x55),
        keyVersion: 2n,
      });
      expect(typeof out.keyVersion).toBe("bigint");
    });

    it("parseUserOpValidationRejected maps the reason enum", () => {
      const log = makeLog(
        shrincsWalletAbi as Abi,
        ADDR_A,
        "UserOpValidationRejected",
        { reason: UserOpValidationFailure.InvalidSignature }
      );
      const [out] = parseUserOpValidationRejected([log]);
      expect(out.reason).toBe(UserOpValidationFailure.InvalidSignature);
      expect(out.reason).toBe(3);
    });

    it("parseUserOpValidationRejected round-trips every enum member", () => {
      for (const reason of [
        UserOpValidationFailure.BadSignatureLength,
        UserOpValidationFailure.StaleStatefulLeaf,
        UserOpValidationFailure.StatefulBudgetExhausted,
        UserOpValidationFailure.InvalidSignature,
      ]) {
        const log = makeLog(
          shrincsWalletAbi as Abi,
          ADDR_A,
          "UserOpValidationRejected",
          { reason }
        );
        expect(parseUserOpValidationRejected([log])[0].reason).toBe(reason);
      }
    });
  });

  describe("paymaster events", () => {
    it("parsePaymasterInitialized", () => {
      const log = makeLog(
        shrincsPaymasterAbi as Abi,
        ADDR_A,
        "PaymasterInitialized",
        { owner: ADDR_B }
      );
      expect(parsePaymasterInitialized([log])).toEqual([{ owner: ADDR_B }]);
    });

    it("parseShrincsVerifierSet", () => {
      const log = makeLog(
        shrincsPaymasterAbi as Abi,
        ADDR_A,
        "ShrincsVerifierSet",
        {
          previousCommitment: B32(0x60),
          newCommitment: B32(0x70),
          parameterSetId: 0,
          maxSignatures: 8,
          keyVersion: 1n,
        }
      );
      const [out] = parseShrincsVerifierSet([log]);
      expect(out).toEqual({
        previousCommitment: B32(0x60),
        newCommitment: B32(0x70),
        parameterSetId: 0,
        maxSignatures: 8,
        keyVersion: 1n,
      });
      expect(typeof out.maxSignatures).toBe("number");
      expect(typeof out.keyVersion).toBe("bigint");
    });

    it("parseSponsorshipVerified", () => {
      const log = makeLog(
        shrincsPaymasterAbi as Abi,
        ADDR_A,
        "SponsorshipVerified",
        { wallet: ADDR_B, leaf: 4, keyVersion: 6n }
      );
      const [out] = parseSponsorshipVerified([log]);
      expect(out).toEqual({ wallet: ADDR_B, leaf: 4, keyVersion: 6n });
      expect(typeof out.leaf).toBe("number");
      expect(typeof out.keyVersion).toBe("bigint");
    });

    it("parsePaymasterValidationRejected maps the reason enum", () => {
      const log = makeLog(
        shrincsPaymasterAbi as Abi,
        ADDR_A,
        "PaymasterValidationRejected",
        { wallet: ADDR_B, reason: PaymasterValidationFailure.StaleStatefulLeaf }
      );
      const [out] = parsePaymasterValidationRejected([log]);
      expect(out.wallet).toBe(ADDR_B);
      expect(out.reason).toBe(PaymasterValidationFailure.StaleStatefulLeaf);
      expect(out.reason).toBe(1);
    });

    it("parsePaymasterValidationRejected round-trips every enum member", () => {
      for (const reason of [
        PaymasterValidationFailure.MalformedPayload,
        PaymasterValidationFailure.StaleStatefulLeaf,
        PaymasterValidationFailure.InvalidSignature,
        PaymasterValidationFailure.StatefulBudgetExhausted,
      ]) {
        const log = makeLog(
          shrincsPaymasterAbi as Abi,
          ADDR_A,
          "PaymasterValidationRejected",
          { wallet: ADDR_B, reason }
        );
        expect(parsePaymasterValidationRejected([log])[0].reason).toBe(reason);
      }
    });

    it("parseUserOpSponsored", () => {
      const log = makeLog(shrincsPaymasterAbi as Abi, ADDR_A, "UserOpSponsored", {
        wallet: ADDR_B,
        mode: 0,
        actualGasCost: 12_345n,
        actualUserOpFeePerGas: 99n,
      });
      const [out] = parseUserOpSponsored([log]);
      expect(out).toEqual({
        wallet: ADDR_B,
        mode: 0,
        actualGasCost: 12_345n,
        actualUserOpFeePerGas: 99n,
      });
      expect(typeof out.mode).toBe("number");
      expect(typeof out.actualGasCost).toBe("bigint");
    });
  });

  describe("multi-log filtering", () => {
    it("returns only matching events when several logs are present", () => {
      const a = makeLog(shrincsWalletAbi as Abi, ADDR_A, "LeafConsumedOnly", {
        leaf: 1,
      });
      const b = makeLog(
        shrincsWalletAbi as Abi,
        ADDR_A,
        "StatefulSignatureVerified",
        { leaf: 2, keyVersion: 0n }
      );
      expect(parseLeafConsumedOnly([a, b])).toEqual([{ leaf: 1 }]);
      expect(parseStatefulSignatureVerified([a, b])).toEqual([
        { leaf: 2, keyVersion: 0n },
      ]);
    });
  });
});
