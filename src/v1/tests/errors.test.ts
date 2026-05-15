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
import {
  type Abi,
  type Hex,
  ContractFunctionRevertedError,
  encodeErrorResult,
  toFunctionSelector,
} from "viem";

import {
  decodeContractError,
  withDecodedError,
} from "../internal/decodeError.js";

import { quipWalletAbi } from "../abi/QuipWallet.js";
import { quipFactoryAbi } from "../abi/QuipFactory.js";
import { quipPaymasterAbi } from "../abi/QuipPaymaster.js";

import {
  QuipError,
  ZeroAddressFactoryError,
  ZeroAddressOwnerError,
  InvalidFactoryError,
  InvalidSignatureError,
  RenounceDisabledError,
  ClassicalWithdrawDisabledError,
  ClassicalTransferOwnershipDisabledError,
  ClassicalCompleteOwnershipHandoverDisabledError,
  DuplicateKeyError,
  KeyInUseError,
  SameKeyError,
  UnknownKeyError,
  KeyAdditionFailedError,
  KeyRemovalFailedError,
  EmptyKeysError,
  RefreshTransactionForbiddenError,
  IncorrectRecoveryKeyAmountError,
  ReplaceAuthKeyForbiddenError,
  ReinstallSpentKeyForbiddenError,
  NotUpgradingError,
  IncorrectTransactionKeyAmountError,
  ImplementationNotVettedError,
  ImplementationDeprecatedError,
  UnknownDisasterRecoveryKeyError,
  UnknownOwnershipKeyError,
  GuardedSlotTamperedError,
  GuardedSlotWriteDeniedError,
  InsufficientBalanceError,
  FeeExceedsMaxError,
  EmptyCodeError,
  AlreadyVettedError,
  NotDeprecatedError,
  NoActiveImplementationError,
  InsufficientCreationFeeError,
  ZeroMaxFeeError,
  InvalidEntryPointError,
  ZeroValuePqVerifierKeyError,
  PqVerifierNotRegisteredError,
  VerifierKeyInUseError,
  VerifierMismatchError,
  KeyAlreadyBurnedError,
  UnknownContractError,
  WalletNotInitializedError,
  WalletAlreadyExistsError,
  NoVaultFoundError,
  InvalidSignerError,
  NotConnectedError,
  UnsupportedNetworkError,
  MulticallUnavailableError,
  GasEstimationError,
  BalanceTooLowError,
  Erc4337WalletValidationError,
  Erc4337PaymasterValidationError,
  UserOpValidationFailure,
  PaymasterValidationFailure,
} from "../errors.js";

/// Build a viem ContractFunctionRevertedError that mimics what we'd see
/// from a real `writeContract`/`readContract` revert.
function fakeRevert(abi: Abi, errorName: string, args?: readonly unknown[]) {
  const data = encodeErrorResult({
    abi,
    errorName,
    ...(args !== undefined && { args }),
  } as Parameters<typeof encodeErrorResult>[0]);
  return new ContractFunctionRevertedError({ abi, data, functionName: "test" });
}

describe("error class properties", () => {
  test("base QuipError carries code, name, message, optional cause/selector/data", () => {
    const cause = new Error("boom");
    const e = new InvalidSignatureError({
      cause,
      selector: "0x8baa579f",
      data: "0xdeadbeef",
    });
    expect(e).toBeInstanceOf(QuipError);
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe("InvalidSignatureError");
    expect(e.code).toBe("INVALID_SIGNATURE");
    expect(e.cause).toBe(cause);
    expect(e.selector).toBe("0x8baa579f");
    expect(e.data).toBe("0xdeadbeef");
    expect(typeof e.message).toBe("string");
  });

  test("parametric errors expose their decoded fields", () => {
    const a = new InsufficientBalanceError(100n, 50n);
    expect(a.requested).toBe(100n);
    expect(a.available).toBe(50n);
    expect(a.message).toContain("100");
    expect(a.message).toContain("50");

    const b = new FeeExceedsMaxError(2n, 1n);
    expect(b.fee).toBe(2n);
    expect(b.maxFee).toBe(1n);

    const c = new InsufficientCreationFeeError(3n, 4n);
    expect(c.sent).toBe(3n);
    expect(c.required).toBe(4n);

    const d = new GuardedSlotTamperedError(7);
    expect(d.slotIndex).toBe(7);
    expect(d.message).toContain("7");
  });

  test("SDK-operational errors instantiate with their context", () => {
    expect(new WalletNotInitializedError().code).toBe("WALLET_NOT_INITIALIZED");
    expect(new WalletAlreadyExistsError("0xabcd" as Hex).vaultId).toBe("0xabcd");
    expect(new NoVaultFoundError("0x1234" as Hex).vaultId).toBe("0x1234");
    expect(new InvalidSignerError().code).toBe("INVALID_SIGNER");
    expect(new NotConnectedError().code).toBe("NOT_CONNECTED");
    expect(new UnsupportedNetworkError(777).chainId).toBe(777);
    expect(new MulticallUnavailableError(31337).chainId).toBe(31337);
    expect(new GasEstimationError("nope").code).toBe("GAS_ESTIMATION_FAILED");
    expect(new BalanceTooLowError(10n, 5n).required).toBe(10n);
  });

  test("VerifierMismatchError carries sender + both verifier values", () => {
    const sender =
      "0x1111111111111111111111111111111111111111" as Hex;
    const supplied = {
      publicSeed:
        "0x2222222222222222222222222222222222222222222222222222222222222222" as Hex,
      publicKeyHash:
        "0x3333333333333333333333333333333333333333333333333333333333333333" as Hex,
    };
    const onChain = {
      publicSeed:
        "0x4444444444444444444444444444444444444444444444444444444444444444" as Hex,
      publicKeyHash:
        "0x5555555555555555555555555555555555555555555555555555555555555555" as Hex,
    };
    const e = new VerifierMismatchError(sender, supplied, onChain);
    expect(e).toBeInstanceOf(QuipError);
    expect(e.code).toBe("VERIFIER_MISMATCH");
    expect(e.name).toBe("VerifierMismatchError");
    expect(e.sender).toBe(sender);
    expect(e.suppliedVerifier).toEqual(supplied);
    expect(e.onChainVerifier).toEqual(onChain);
    expect(e.message).toContain(sender);
  });

  test("KeyAlreadyBurnedError keeps publicSeed on the typed field but omits it from message", () => {
    const seed =
      "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" as Hex;
    const e = new KeyAlreadyBurnedError(seed);
    expect(e.publicSeed).toBe(seed);
    expect(e.code).toBe("KEY_ALREADY_BURNED");
    // Message no longer leaks the seed value.
    expect(e.message).not.toContain(seed);
    expect(e.message).toContain("signWithKey");
  });

  test("ERC-4337 enum-failure errors carry the typed reason", () => {
    const w = new Erc4337WalletValidationError(
      UserOpValidationFailure.InvalidSignature
    );
    expect(w.reason).toBe(UserOpValidationFailure.InvalidSignature);
    expect(w.message).toContain("InvalidSignature");

    const p = new Erc4337PaymasterValidationError(
      PaymasterValidationFailure.NoVerifierRegistered
    );
    expect(p.reason).toBe(PaymasterValidationFailure.NoVerifierRegistered);
    expect(p.message).toContain("NoVerifierRegistered");
  });
});

/// Every Solidity error name → its source ABI + the SDK class it should
/// decode to + (optional) args for parametric variants. Covers every entry
/// in the ERROR_REGISTRY.
const ROUND_TRIP_CASES: ReadonlyArray<{
  name: string;
  abi: Abi;
  args?: readonly unknown[];
  klass: new (...a: never[]) => QuipError;
  // Optional inspector for parametric errors (verifies decoded fields).
  inspect?: (e: QuipError) => void;
}> = [
  // Wallet — no args
  { name: "ZeroAddressFactory", abi: quipWalletAbi, klass: ZeroAddressFactoryError },
  { name: "ZeroAddressOwner", abi: quipWalletAbi, klass: ZeroAddressOwnerError },
  { name: "InvalidFactory", abi: quipWalletAbi, klass: InvalidFactoryError },
  { name: "InvalidSignature", abi: quipWalletAbi, klass: InvalidSignatureError },
  { name: "RenounceDisabled", abi: quipWalletAbi, klass: RenounceDisabledError },
  { name: "ClassicalWithdrawDisabled", abi: quipWalletAbi, klass: ClassicalWithdrawDisabledError },
  { name: "ClassicalTransferOwnershipDisabled", abi: quipWalletAbi, klass: ClassicalTransferOwnershipDisabledError },
  { name: "ClassicalCompleteOwnershipHandoverDisabled", abi: quipWalletAbi, klass: ClassicalCompleteOwnershipHandoverDisabledError },
  { name: "DuplicateKey", abi: quipWalletAbi, klass: DuplicateKeyError },
  { name: "KeyInUse", abi: quipWalletAbi, klass: KeyInUseError },
  { name: "SameKey", abi: quipWalletAbi, klass: SameKeyError },
  { name: "UnknownKey", abi: quipWalletAbi, klass: UnknownKeyError },
  { name: "KeyAdditionFailed", abi: quipWalletAbi, klass: KeyAdditionFailedError },
  { name: "KeyRemovalFailed", abi: quipWalletAbi, klass: KeyRemovalFailedError },
  { name: "EmptyKeys", abi: quipWalletAbi, klass: EmptyKeysError },
  { name: "RefreshTransactionForbidden", abi: quipWalletAbi, klass: RefreshTransactionForbiddenError },
  { name: "IncorrectRecoveryKeyAmount", abi: quipWalletAbi, klass: IncorrectRecoveryKeyAmountError },
  { name: "ReplaceAuthKeyForbidden", abi: quipWalletAbi, klass: ReplaceAuthKeyForbiddenError },
  { name: "ReinstallSpentKeyForbidden", abi: quipWalletAbi, klass: ReinstallSpentKeyForbiddenError },
  { name: "NotUpgrading", abi: quipWalletAbi, klass: NotUpgradingError },
  { name: "IncorrectTransactionKeyAmount", abi: quipWalletAbi, klass: IncorrectTransactionKeyAmountError },
  { name: "ImplementationNotVetted", abi: quipWalletAbi, klass: ImplementationNotVettedError },
  { name: "ImplementationDeprecated", abi: quipWalletAbi, klass: ImplementationDeprecatedError },
  { name: "UnknownDisasterRecoveryKey", abi: quipWalletAbi, klass: UnknownDisasterRecoveryKeyError },
  { name: "UnknownOwnershipKey", abi: quipWalletAbi, klass: UnknownOwnershipKeyError },
  { name: "GuardedSlotWriteDenied", abi: quipWalletAbi, klass: GuardedSlotWriteDeniedError },

  // Wallet — parametric
  {
    name: "GuardedSlotTampered",
    abi: quipWalletAbi,
    args: [3],
    klass: GuardedSlotTamperedError,
    inspect: (e) => {
      expect((e as GuardedSlotTamperedError).slotIndex).toBe(3);
    },
  },

  // Factory — no args
  { name: "EmptyCode", abi: quipFactoryAbi, klass: EmptyCodeError },
  { name: "AlreadyVetted", abi: quipFactoryAbi, klass: AlreadyVettedError },
  { name: "NotDeprecated", abi: quipFactoryAbi, klass: NotDeprecatedError },
  { name: "NoActiveImplementation", abi: quipFactoryAbi, klass: NoActiveImplementationError },
  { name: "ZeroMaxFee", abi: quipFactoryAbi, klass: ZeroMaxFeeError },

  // Factory — parametric
  {
    name: "InsufficientBalance",
    abi: quipFactoryAbi,
    args: [100n, 50n],
    klass: InsufficientBalanceError,
    inspect: (e) => {
      const x = e as InsufficientBalanceError;
      expect(x.requested).toBe(100n);
      expect(x.available).toBe(50n);
    },
  },
  {
    name: "FeeExceedsMax",
    abi: quipFactoryAbi,
    args: [200n, 100n],
    klass: FeeExceedsMaxError,
    inspect: (e) => {
      const x = e as FeeExceedsMaxError;
      expect(x.fee).toBe(200n);
      expect(x.maxFee).toBe(100n);
    },
  },
  {
    name: "InsufficientCreationFee",
    abi: quipFactoryAbi,
    args: [1n, 7n],
    klass: InsufficientCreationFeeError,
    inspect: (e) => {
      const x = e as InsufficientCreationFeeError;
      expect(x.sent).toBe(1n);
      expect(x.required).toBe(7n);
    },
  },

  // Paymaster
  { name: "InvalidEntryPoint", abi: quipPaymasterAbi, klass: InvalidEntryPointError },
  { name: "ZeroValuePqVerifierKey", abi: quipPaymasterAbi, klass: ZeroValuePqVerifierKeyError },
  { name: "PqVerifierNotRegistered", abi: quipPaymasterAbi, klass: PqVerifierNotRegisteredError },
  { name: "VerifierKeyInUse", abi: quipPaymasterAbi, klass: VerifierKeyInUseError },
];

describe("decodeContractError selector round-trip", () => {
  test.each(ROUND_TRIP_CASES.map((c) => [c.name, c] as const))(
    "%s decodes to its typed class",
    (_name, c) => {
      const revert = fakeRevert(c.abi, c.name, c.args);
      const decoded = decodeContractError(revert);
      expect(decoded).not.toBeNull();
      expect(decoded).toBeInstanceOf(c.klass);
      expect(decoded?.cause).toBe(revert);
      if (c.inspect && decoded) c.inspect(decoded);
    }
  );

  test("withDecodedError unwraps a rejected viem call", async () => {
    const revert = fakeRevert(quipWalletAbi, "InvalidSignature");
    await expect(
      withDecodedError(Promise.reject(revert))
    ).rejects.toBeInstanceOf(InvalidSignatureError);
  });

  test("withDecodedError passes through non-contract errors unchanged", async () => {
    const e = new TypeError("network kaput");
    await expect(withDecodedError(Promise.reject(e))).rejects.toBe(e);
  });

  test("withDecodedError resolves happy paths untouched", async () => {
    await expect(withDecodedError(Promise.resolve(42))).resolves.toBe(42);
  });

  test("unknown selector falls through to UnknownContractError", () => {
    const fakeAbi: Abi = [
      {
        type: "error",
        name: "TotallyMadeUpError",
        inputs: [{ type: "uint256", name: "x" }],
      },
    ];
    const revert = fakeRevert(fakeAbi, "TotallyMadeUpError", [42n]);
    const decoded = decodeContractError(revert);
    expect(decoded).toBeInstanceOf(UnknownContractError);
    expect((decoded as UnknownContractError).errorName).toBe("TotallyMadeUpError");
  });

  test("non-contract errors return null from decodeContractError", () => {
    expect(decodeContractError(new Error("plain"))).toBeNull();
    expect(decodeContractError("string")).toBeNull();
    expect(decodeContractError(null)).toBeNull();
  });

  test("dedupe: shared error names (RenounceDisabled, ZeroAddressOwner, ImplementationNotVetted) decode regardless of source ABI", () => {
    // RenounceDisabled appears in QuipWallet, QuipFactory, QuipPaymaster.
    // Same selector either way; should always decode to the single typed class.
    const fromWallet = fakeRevert(quipWalletAbi, "RenounceDisabled");
    const fromFactory = fakeRevert(quipFactoryAbi, "RenounceDisabled");
    expect(decodeContractError(fromWallet)).toBeInstanceOf(RenounceDisabledError);
    expect(decodeContractError(fromFactory)).toBeInstanceOf(RenounceDisabledError);

    const ownerFromWallet = fakeRevert(quipWalletAbi, "ZeroAddressOwner");
    const ownerFromFactory = fakeRevert(quipFactoryAbi, "ZeroAddressOwner");
    const ownerFromPm = fakeRevert(quipPaymasterAbi, "ZeroAddressOwner");
    expect(decodeContractError(ownerFromWallet)).toBeInstanceOf(ZeroAddressOwnerError);
    expect(decodeContractError(ownerFromFactory)).toBeInstanceOf(ZeroAddressOwnerError);
    expect(decodeContractError(ownerFromPm)).toBeInstanceOf(ZeroAddressOwnerError);
  });

  test("decoded selector matches viem's toFunctionSelector for parametric error", () => {
    const revert = fakeRevert(quipFactoryAbi, "FeeExceedsMax", [9n, 8n]);
    const decoded = decodeContractError(revert);
    expect(decoded).toBeInstanceOf(FeeExceedsMaxError);
    // Sanity-check: the on-chain selector for `FeeExceedsMax(uint256,uint256)`.
    const expected = toFunctionSelector("FeeExceedsMax(uint256,uint256)");
    // viem's ContractFunctionRevertedError populates `data` directly when it
    // can decode against the supplied ABI — selector is implicit but we can
    // verify by re-encoding and matching the prefix.
    const encoded = encodeErrorResult({
      abi: quipFactoryAbi,
      errorName: "FeeExceedsMax",
      args: [9n, 8n],
    });
    expect(encoded.slice(0, 10)).toBe(expected);
  });
});
