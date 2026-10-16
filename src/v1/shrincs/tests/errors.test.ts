// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type Hex, encodeErrorResult, toFunctionSelector } from "viem";

import { wotsPlusImplementationAbi } from "../../abi/WOTSPlusImplementation.js";
import {
  DuplicateKeyError,
  UnknownContractError as V1UnknownContractError,
} from "../../errors.js";
import { makeErrorDecoder } from "../../internal/errorDecoder.js";
import { decodeRevertBytes as decodeV1RevertBytes } from "../../internal/decodeError.js";
import { shrincsPaymasterAbi } from "../abi/ShrincsPaymaster.js";
import { shrincsWalletAbi } from "../abi/ShrincsWallet.js";
import { shrincsWalletBeta2Abi } from "../versions/v1_0_1_beta2/abi.js";
import {
  GuardedSlotTamperedError,
  InvalidSignatureError,
  MalformedCodecPayloadError,
  StaleStatefulLeafError,
  StatefulBudgetExhaustedError,
  IdentityMismatchError,
  VerifierProfileMismatchError,
  UpgradeFailedError,
  ZeroErc1271CommitmentError,
  AlreadyInitializedError,
  StatefulTreeSpentError,
  StatelessTreeSpentError,
  UnknownContractError,
  InvalidOwnerAcceptanceError,
  InvalidKeyAcceptanceError,
} from "../errors.js";
import { decodeRevertBytes } from "../internal/decodeError.js";

describe("shrincs error decoding", () => {
  it("decodes a zero-arg wallet error to its typed class", () => {
    const data = encodeErrorResult({ abi: shrincsWalletAbi, errorName: "StaleStatefulLeaf" });
    const decoded = decodeRevertBytes(data);
    expect(decoded).toBeInstanceOf(StaleStatefulLeafError);
    expect(decoded?.code).toBe("SHRINCS_STALE_STATEFUL_LEAF");
    expect(decoded?.selector).toBe(toFunctionSelector("StaleStatefulLeaf()"));
  });

  it("decodes StatefulBudgetExhausted and InvalidSignature", () => {
    expect(
      decodeRevertBytes(encodeErrorResult({ abi: shrincsWalletAbi, errorName: "StatefulBudgetExhausted" }))
    ).toBeInstanceOf(StatefulBudgetExhaustedError);
    expect(
      decodeRevertBytes(encodeErrorResult({ abi: shrincsWalletAbi, errorName: "InvalidSignature" }))
    ).toBeInstanceOf(InvalidSignatureError);
  });

  it("decodes the transferOwnership acceptance errors (current wallet)", () => {
    const owner = decodeRevertBytes(
      encodeErrorResult({ abi: shrincsWalletAbi, errorName: "InvalidOwnerAcceptance" })
    );
    expect(owner).toBeInstanceOf(InvalidOwnerAcceptanceError);
    expect(owner?.code).toBe("SHRINCS_INVALID_OWNER_ACCEPTANCE");
    expect(owner?.selector).toBe(toFunctionSelector("InvalidOwnerAcceptance()"));
    const key = decodeRevertBytes(
      encodeErrorResult({ abi: shrincsWalletAbi, errorName: "InvalidKeyAcceptance" })
    );
    expect(key).toBeInstanceOf(InvalidKeyAcceptanceError);
    expect(key?.code).toBe("SHRINCS_INVALID_KEY_ACCEPTANCE");
    expect(key?.selector).toBe(toFunctionSelector("InvalidKeyAcceptance()"));
  });

  it("decodes MalformedPayload(uint256,uint256) preserving args", () => {
    const data = encodeErrorResult({
      abi: shrincsWalletAbi,
      errorName: "MalformedPayload",
      args: [64n, 12n],
    });
    const decoded = decodeRevertBytes(data) as MalformedCodecPayloadError;
    expect(decoded).toBeInstanceOf(MalformedCodecPayloadError);
    expect(decoded.expectedMin).toBe(64n);
    expect(decoded.actual).toBe(12n);
  });

  it("decodes IdentityMismatch and VerifierProfileMismatch (current wallet)", () => {
    expect(
      decodeRevertBytes(
        encodeErrorResult({ abi: shrincsWalletAbi, errorName: "IdentityMismatch" })
      )
    ).toBeInstanceOf(IdentityMismatchError);
    expect(
      decodeRevertBytes(
        encodeErrorResult({
          abi: shrincsWalletAbi,
          errorName: "VerifierProfileMismatch",
        })
      )
    ).toBeInstanceOf(VerifierProfileMismatchError);
  });

  it("decodes UpgradeFailed (solady UUPS) and InvalidInitialization", () => {
    expect(
      decodeRevertBytes(
        encodeErrorResult({ abi: shrincsWalletAbi, errorName: "UpgradeFailed" })
      )
    ).toBeInstanceOf(UpgradeFailedError);
    expect(
      decodeRevertBytes(
        encodeErrorResult({
          abi: shrincsWalletAbi,
          errorName: "InvalidInitialization",
        })
      )
    ).toBeInstanceOf(AlreadyInitializedError);
  });

  it("decodes ZeroErc1271Commitment from a beta.2 wallet", () => {
    expect(
      decodeRevertBytes(
        encodeErrorResult({
          abi: shrincsWalletBeta2Abi,
          errorName: "ZeroErc1271Commitment",
        })
      )
    ).toBeInstanceOf(ZeroErc1271CommitmentError);
  });

  // `GuardedSlotTampered` was removed from the CURRENT wallet (the STATICCALL
  // probe replaced the guarded-slot snapshot) but deployed V1.0.1-beta.2 wallets
  // still throw it, so it must stay decodable via the frozen beta.2 ABI.
  it("decodes GuardedSlotTampered(uint256) from a beta.2 wallet, preserving the slot index", () => {
    const data = encodeErrorResult({
      abi: shrincsWalletBeta2Abi,
      errorName: "GuardedSlotTampered",
      args: [7n],
    });
    const decoded = decodeRevertBytes(data) as GuardedSlotTamperedError;
    expect(decoded).toBeInstanceOf(GuardedSlotTamperedError);
    expect(decoded.slotIndex).toBe(7);
  });

  it("decodes StatefulTreeSpent(bytes32) from the wallet and paymaster ABIs preserving treeId", () => {
    const treeId = ("0x" + "ab".repeat(32)) as Hex;
    for (const abi of [shrincsWalletAbi, shrincsPaymasterAbi]) {
      const data = encodeErrorResult({ abi, errorName: "StatefulTreeSpent", args: [treeId] });
      const decoded = decodeRevertBytes(data) as StatefulTreeSpentError;
      expect(decoded).toBeInstanceOf(StatefulTreeSpentError);
      expect(decoded.code).toBe("SHRINCS_STATEFUL_TREE_SPENT");
      expect(decoded.treeId).toBe(treeId);
      expect(decoded.selector).toBe(toFunctionSelector("StatefulTreeSpent(bytes32)"));
    }
  });

  it("decodes truncated StatefulTreeSpent args as treeId undefined", () => {
    const selector = toFunctionSelector("StatefulTreeSpent(bytes32)");
    const truncated = `${selector}abcd` as Hex;
    const decoded = decodeRevertBytes(truncated) as StatefulTreeSpentError;
    expect(decoded).toBeInstanceOf(StatefulTreeSpentError);
    expect(decoded.code).toBe("SHRINCS_STATEFUL_TREE_SPENT");
    expect(decoded.treeId).toBeUndefined();
  });

  it("StatefulTreeSpentError(undefined) uses the no-id message", () => {
    const err = new StatefulTreeSpentError(undefined);
    expect(err.treeId).toBeUndefined();
    expect(err.code).toBe("SHRINCS_STATEFUL_TREE_SPENT");
    expect(err.message).toBe(
      "Stateful tree was already installed on this contract — keygen a fresh key"
    );
  });

  it("decodes StatelessTreeSpent(bytes32) preserving treeId", () => {
    const treeId = ("0x" + "cd".repeat(32)) as Hex;
    const data = encodeErrorResult({
      abi: shrincsWalletAbi,
      errorName: "StatelessTreeSpent",
      args: [treeId],
    });
    const decoded = decodeRevertBytes(data) as StatelessTreeSpentError;
    expect(decoded).toBeInstanceOf(StatelessTreeSpentError);
    expect(decoded.code).toBe("SHRINCS_STATELESS_TREE_SPENT");
    expect(decoded.treeId).toBe(treeId);
  });

  it("maps an unknown 4-byte selector to UnknownContractError, and empty data to null", () => {
    expect(decodeRevertBytes("0xdeadbeef")).toBeInstanceOf(UnknownContractError);
    expect(decodeRevertBytes("0x")).toBeNull();
  });
});

describe("registry-parameterized error decoder", () => {
  it("decodes a v1-only error and a shrincs-only error through the shared core, keeping registries distinct", () => {
    const v1Data = encodeErrorResult({
      abi: wotsPlusImplementationAbi,
      errorName: "DuplicateKey",
    });
    const shrincsData = encodeErrorResult({
      abi: shrincsWalletAbi,
      errorName: "StaleStatefulLeaf",
    });

    const v1 = makeErrorDecoder({
      abis: [wotsPlusImplementationAbi],
      errorMap: {
        DuplicateKey: (_args, opts) => new DuplicateKeyError(opts),
      },
      unknownError: (name, args, opts) =>
        new V1UnknownContractError(name, args, opts),
    });
    const shrincs = makeErrorDecoder({
      abis: [shrincsWalletAbi],
      errorMap: {
        StaleStatefulLeaf: (_args, opts) =>
          new StaleStatefulLeafError(undefined, opts),
      },
      unknownError: (name, args, opts) =>
        new UnknownContractError(name, args, opts),
    });

    expect(v1.decodeRevertBytes(v1Data)).toBeInstanceOf(DuplicateKeyError);
    expect(shrincs.decodeRevertBytes(shrincsData)).toBeInstanceOf(
      StaleStatefulLeafError
    );
    expect(v1.decodeRevertBytes(shrincsData)).toBeInstanceOf(
      V1UnknownContractError
    );
    expect(shrincs.decodeRevertBytes(v1Data)).toBeInstanceOf(
      UnknownContractError
    );

    expect(decodeV1RevertBytes(v1Data)).toBeInstanceOf(DuplicateKeyError);
    expect(decodeRevertBytes(shrincsData)).toBeInstanceOf(
      StaleStatefulLeafError
    );
    expect(decodeV1RevertBytes(shrincsData)).toBeInstanceOf(
      V1UnknownContractError
    );
    expect(decodeRevertBytes(v1Data)).toBeInstanceOf(UnknownContractError);
  });
});
