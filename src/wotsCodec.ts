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
  type Address,
  type Hex,
  concat,
  encodeAbiParameters,
  getAddress,
  hexToBigInt,
  keccak256,
  pad,
  size,
  slice,
  toHex,
} from "viem";

/// The ABI expects bytes32[67] for a WOTS+ signature; this fixed-length tuple
/// is what viem requires for typed argument passing.
export type Bytes32Tuple67 = readonly [
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex,
];

export interface WinternitzAddress {
  publicSeed: Hex;
  publicKeyHash: Hex;
}

export interface WinternitzElements {
  elements: Hex[];
}

/// Mirrors `IQuipWallet.KeyType`. Same enum, also exported from
/// `walletClient.ts`; this copy lets codec consumers avoid pulling in the
/// full client module.
export enum KeyType {
  Transaction = 0,
  Recovery = 1,
  Verification = 2,
}

export const WOTS_ADDRESS_SIZE = 64;
export const WOTS_ELEMENTS_SIZE = 2144;
export const WOTS_ELEMENTS_COUNT = 67;
export const TRANSACTION_KEY_INIT_AMOUNT = 5;
export const RECOVERY_KEY_AMOUNT = 10;

// Domain tags — keccak256 of stable string identifiers, must match
// `WOTSPlusCodec.sol` exactly. Distinct tags per operation are load-bearing
// security: removing or unifying any tag would let a signature authorizing
// one flow be replayed against another.
export const EXECUTE_TAG: Hex = keccak256(toHex("quip.digest.execute"));
export const KEY_MGMT_TAG: Hex = keccak256(toHex("quip.digest.keyManagement"));
export const ADD_TRANSACTION_KEYS_TAG: Hex = keccak256(
  toHex("quip.digest.addTransactionKeys")
);
export const VERIFICATION_KEYS_TAG: Hex = keccak256(
  toHex("quip.digest.verificationKeys")
);
export const UPGRADE_TAG: Hex = keccak256(toHex("quip.digest.upgrade"));
export const VERIFICATION_TAG: Hex = keccak256(
  toHex("quip.digest.verification")
);
export const UPGRADE_RECOVERY_TAG: Hex = keccak256(
  toHex("quip.digest.upgradeRecovery")
);
export const ERC4337_EXECUTE_TAG: Hex = keccak256(
  toHex("quip.digest.erc4337Execute")
);
export const WITHDRAW_DEPOSIT_TAG: Hex = keccak256(
  toHex("quip.digest.withdrawDeposit")
);
export const TRANSFER_OWNERSHIP_TAG: Hex = keccak256(
  toHex("quip.digest.transferOwnership")
);
export const COMPLETE_OWNERSHIP_HANDOVER_TAG: Hex = keccak256(
  toHex("quip.digest.completeOwnershipHandover")
);
export const REPLACE_TRANSACTION_KEY_AT_TAG: Hex = keccak256(
  toHex("quip.digest.replaceTransactionKeyAt")
);
export const REPLACE_RECOVERY_KEY_AT_TAG: Hex = keccak256(
  toHex("quip.digest.replaceRecoveryKeyAt")
);
export const REPLACE_VERIFICATION_KEY_AT_TAG: Hex = keccak256(
  toHex("quip.digest.replaceVerificationKeyAt")
);
export const ERC1271_TAG: Hex = keccak256(toHex("quip.digest.erc1271"));
export const SAVE_WALLET_TAG: Hex = keccak256(
  toHex("quip.digest.saveWallet")
);
export const RECOVER_WALLET_TAG: Hex = keccak256(
  toHex("quip.digest.recoverWallet")
);
export const PAYMASTER_APPROVE_TAG: Hex = keccak256(
  toHex("quip.digest.paymasterApprove")
);

function packAddress(addr: WinternitzAddress): Hex {
  return concat([addr.publicSeed, addr.publicKeyHash]);
}

function packElements(sig: WinternitzElements): Hex {
  return concat(sig.elements);
}

function sliceAddress(data: Hex, offset: number): WinternitzAddress {
  return {
    publicSeed: slice(data, offset, offset + 32),
    publicKeyHash: slice(data, offset + 32, offset + 64),
  };
}

function sliceElements(data: Hex, offset: number): WinternitzElements {
  const elements: Hex[] = [];
  for (let i = 0; i < WOTS_ELEMENTS_COUNT; i++) {
    elements.push(slice(data, offset + i * 32, offset + (i + 1) * 32));
  }
  return { elements };
}

function addressToBytes32(addr: Address): Hex {
  return pad(addr as Hex, { size: 32, dir: "left" });
}

function bigintToBytes32(value: bigint | number): Hex {
  return toHex(BigInt(value), { size: 32 });
}

function tagForKeyset(kind: KeyType | number): Hex {
  if (kind === KeyType.Transaction) return ADD_TRANSACTION_KEYS_TAG;
  if (kind === KeyType.Verification) return VERIFICATION_KEYS_TAG;
  return KEY_MGMT_TAG; // Recovery
}

function tagForReplaceKeyAt(kind: KeyType | number): Hex {
  if (kind === KeyType.Transaction) return REPLACE_TRANSACTION_KEY_AT_TAG;
  if (kind === KeyType.Recovery) return REPLACE_RECOVERY_KEY_AT_TAG;
  return REPLACE_VERIFICATION_KEY_AT_TAG;
}

/// Mirrors the contract's `keccak256(abi.encode(keys))` over a
/// `WinternitzAddress[]`. Used as the bound payload-hash inside
/// `keysetDigest` so the signature commits to the exact set of keys
/// being added/refreshed.
export function keysHash(keys: WinternitzAddress[]): Hex {
  const encoded = encodeAbiParameters(
    [
      {
        type: "tuple[]",
        components: [
          { type: "bytes32", name: "publicSeed" },
          { type: "bytes32", name: "publicKeyHash" },
        ],
      },
    ],
    [keys]
  );
  return keccak256(encoded);
}

/// keccak256 over arbitrary calldata. Mirrors the contract's
/// `EfficientHashLib.hashCalldata(data)` used inside `executeDigest`.
export function opdataHash(data: Hex): Hex {
  return keccak256(data);
}

/// Init payload (1088 bytes): disasterRecoveryKey + ownershipKey +
/// transactionKeys[5] + recoveryKeys[10].
export function encodeInit(
  disasterRecoveryKey: WinternitzAddress,
  ownershipKey: WinternitzAddress,
  transactionKeys: WinternitzAddress[],
  recoveryKeys: WinternitzAddress[]
): Hex {
  return concat([
    packAddress(disasterRecoveryKey),
    packAddress(ownershipKey),
    ...transactionKeys.map(packAddress),
    ...recoveryKeys.map(packAddress),
  ]);
}

/// Execute payload (>= 2336 bytes): currentKey + nextKey + pqSig + target +
/// value + data. The trailing `data` is variable length.
export function encodeExecute(
  currentKey: WinternitzAddress,
  nextKey: WinternitzAddress,
  pqSig: WinternitzElements,
  target: Address,
  value: bigint,
  data: Hex = "0x"
): Hex {
  return concat([
    packAddress(currentKey),
    packAddress(nextKey),
    packElements(pqSig),
    addressToBytes32(target),
    bigintToBytes32(value),
    data,
  ]);
}

/// RecoverWallet payload (2336 bytes): recoveryKey + newRecoveryKey +
/// newTransactionKey + pqSig.
export function encodeRecoverWallet(
  recoveryKey: WinternitzAddress,
  newRecoveryKey: WinternitzAddress,
  newTransactionKey: WinternitzAddress,
  pqSig: WinternitzElements
): Hex {
  return concat([
    packAddress(recoveryKey),
    packAddress(newRecoveryKey),
    packAddress(newTransactionKey),
    packElements(pqSig),
  ]);
}

/// KeyManagement payload (2304 + N*64 bytes): kind + currentKey + nextKey +
/// pqSig + keys[]. Used for both `addKeys` and `refreshKeys`.
export function encodeKeyManagement(
  kind: KeyType | number,
  currentKey: WinternitzAddress,
  nextKey: WinternitzAddress,
  pqSig: WinternitzElements,
  keys: WinternitzAddress[]
): Hex {
  return concat([
    bigintToBytes32(BigInt(kind)),
    packAddress(currentKey),
    packAddress(nextKey),
    packElements(pqSig),
    ...keys.map(packAddress),
  ]);
}

/// WithdrawDeposit payload (2336 bytes): currentKey + nextKey + pqSig + to +
/// amount.
export function encodeWithdrawDeposit(
  currentKey: WinternitzAddress,
  nextKey: WinternitzAddress,
  pqSig: WinternitzElements,
  to: Address,
  amount: bigint
): Hex {
  return concat([
    packAddress(currentKey),
    packAddress(nextKey),
    packElements(pqSig),
    addressToBytes32(to),
    bigintToBytes32(amount),
  ]);
}

/// ReplaceKeyAt payload (2400 bytes): kind + currentKey + nextKey + pqSig +
/// index + newKey.
export function encodeReplaceKeyAt(
  kind: KeyType | number,
  currentKey: WinternitzAddress,
  nextKey: WinternitzAddress,
  pqSig: WinternitzElements,
  index: bigint,
  newKey: WinternitzAddress
): Hex {
  return concat([
    bigintToBytes32(BigInt(kind)),
    packAddress(currentKey),
    packAddress(nextKey),
    packElements(pqSig),
    bigintToBytes32(index),
    packAddress(newKey),
  ]);
}

/// UserOpSignature payload (2272 bytes): currentKey + nextKey + pqSig.
/// Used for the ERC-4337 `signature` field.
export function encodeUserOpSignature(
  currentKey: WinternitzAddress,
  nextKey: WinternitzAddress,
  pqSig: WinternitzElements
): Hex {
  return concat([
    packAddress(currentKey),
    packAddress(nextKey),
    packElements(pqSig),
  ]);
}

export function decodeInit(payload: Hex): {
  disasterRecoveryKey: WinternitzAddress;
  ownershipKey: WinternitzAddress;
  transactionKeys: WinternitzAddress[];
  recoveryKeys: WinternitzAddress[];
} {
  const disasterRecoveryKey = sliceAddress(payload, 0);
  const ownershipKey = sliceAddress(payload, 64);
  const transactionKeys: WinternitzAddress[] = [];
  for (let i = 0; i < TRANSACTION_KEY_INIT_AMOUNT; i++) {
    transactionKeys.push(sliceAddress(payload, 128 + i * 64));
  }
  const recoveryKeys: WinternitzAddress[] = [];
  for (let i = 0; i < RECOVERY_KEY_AMOUNT; i++) {
    recoveryKeys.push(sliceAddress(payload, 448 + i * 64));
  }
  return { disasterRecoveryKey, ownershipKey, transactionKeys, recoveryKeys };
}

export function decodeExecute(payload: Hex): {
  currentKey: WinternitzAddress;
  nextKey: WinternitzAddress;
  pqSig: WinternitzElements;
  target: Address;
  value: bigint;
  data: Hex;
} {
  return {
    currentKey: sliceAddress(payload, 0),
    nextKey: sliceAddress(payload, 64),
    pqSig: sliceElements(payload, 128),
    target: getAddress(slice(payload, 2284, 2304)),
    value: hexToBigInt(slice(payload, 2304, 2336)),
    data: size(payload) > 2336 ? slice(payload, 2336) : "0x",
  };
}

export function decodeRecoverWallet(payload: Hex): {
  recoveryKey: WinternitzAddress;
  newRecoveryKey: WinternitzAddress;
  newTransactionKey: WinternitzAddress;
  pqSig: WinternitzElements;
} {
  return {
    recoveryKey: sliceAddress(payload, 0),
    newRecoveryKey: sliceAddress(payload, 64),
    newTransactionKey: sliceAddress(payload, 128),
    pqSig: sliceElements(payload, 192),
  };
}

export function decodeKeyManagement(payload: Hex): {
  kind: number;
  currentKey: WinternitzAddress;
  nextKey: WinternitzAddress;
  pqSig: WinternitzElements;
  keys: WinternitzAddress[];
} {
  const payloadSize = size(payload);
  const keyCount = (payloadSize - 2304) / 64;
  const keys: WinternitzAddress[] = [];
  for (let i = 0; i < keyCount; i++) {
    keys.push(sliceAddress(payload, 2304 + i * 64));
  }
  return {
    kind: Number(hexToBigInt(slice(payload, 0, 32))),
    currentKey: sliceAddress(payload, 32),
    nextKey: sliceAddress(payload, 96),
    pqSig: sliceElements(payload, 160),
    keys,
  };
}

export function decodeWithdrawDeposit(payload: Hex): {
  currentKey: WinternitzAddress;
  nextKey: WinternitzAddress;
  pqSig: WinternitzElements;
  to: Address;
  amount: bigint;
} {
  return {
    currentKey: sliceAddress(payload, 0),
    nextKey: sliceAddress(payload, 64),
    pqSig: sliceElements(payload, 128),
    to: getAddress(slice(payload, 2284, 2304)),
    amount: hexToBigInt(slice(payload, 2304, 2336)),
  };
}

export function decodeReplaceKeyAt(payload: Hex): {
  kind: number;
  currentKey: WinternitzAddress;
  nextKey: WinternitzAddress;
  pqSig: WinternitzElements;
  index: bigint;
  newKey: WinternitzAddress;
} {
  return {
    kind: Number(hexToBigInt(slice(payload, 0, 32))),
    currentKey: sliceAddress(payload, 32),
    nextKey: sliceAddress(payload, 96),
    pqSig: sliceElements(payload, 160),
    index: hexToBigInt(slice(payload, 2304, 2336)),
    newKey: sliceAddress(payload, 2336),
  };
}

export function decodeUserOpSignature(payload: Hex): {
  currentKey: WinternitzAddress;
  nextKey: WinternitzAddress;
  pqSig: WinternitzElements;
} {
  return {
    currentKey: sliceAddress(payload, 0),
    nextKey: sliceAddress(payload, 64),
    pqSig: sliceElements(payload, 128),
  };
}

export function executeDigest(
  wallet: Address,
  chainId: bigint,
  s1: Hex,
  h1: Hex,
  s2: Hex,
  h2: Hex,
  target: Address,
  value: bigint,
  opdataHash: Hex,
  fee: bigint
): Hex {
  return keccak256(
    concat([
      EXECUTE_TAG,
      bigintToBytes32(chainId),
      addressToBytes32(wallet),
      s1,
      h1,
      s2,
      h2,
      addressToBytes32(target),
      bigintToBytes32(value),
      opdataHash,
      bigintToBytes32(fee),
    ])
  );
}

/// Mirrors `WOTSPlusCodec.keysetDigest`. `kind` selects the domain tag:
///   Transaction → ADD_TRANSACTION_KEYS_TAG
///   Recovery    → KEY_MGMT_TAG
///   Verification → VERIFICATION_KEYS_TAG
export function keysetDigest(
  kind: KeyType | number,
  wallet: Address,
  chainId: bigint,
  s1: Hex,
  h1: Hex,
  s2: Hex,
  h2: Hex,
  keysHash: Hex
): Hex {
  return keccak256(
    concat([
      tagForKeyset(kind),
      bigintToBytes32(chainId),
      addressToBytes32(wallet),
      s1,
      h1,
      s2,
      h2,
      keysHash,
    ])
  );
}

export function recoverWalletDigest(
  wallet: Address,
  chainId: bigint,
  recoverySeed: Hex,
  recoveryHash: Hex,
  newRecoverySeed: Hex,
  newRecoveryHash: Hex,
  newTransactionSeed: Hex,
  newTransactionHash: Hex
): Hex {
  return keccak256(
    concat([
      RECOVER_WALLET_TAG,
      bigintToBytes32(chainId),
      addressToBytes32(wallet),
      recoverySeed,
      recoveryHash,
      newRecoverySeed,
      newRecoveryHash,
      newTransactionSeed,
      newTransactionHash,
    ])
  );
}

export function withdrawDepositDigest(
  wallet: Address,
  chainId: bigint,
  s1: Hex,
  h1: Hex,
  s2: Hex,
  h2: Hex,
  to: Address,
  amount: bigint
): Hex {
  return keccak256(
    concat([
      WITHDRAW_DEPOSIT_TAG,
      bigintToBytes32(chainId),
      addressToBytes32(wallet),
      s1,
      h1,
      s2,
      h2,
      addressToBytes32(to),
      bigintToBytes32(amount),
    ])
  );
}

export function replaceKeyAtDigest(
  kind: KeyType | number,
  wallet: Address,
  chainId: bigint,
  s1: Hex,
  h1: Hex,
  s2: Hex,
  h2: Hex,
  index: bigint,
  newSeed: Hex,
  newHash: Hex
): Hex {
  return keccak256(
    concat([
      tagForReplaceKeyAt(kind),
      bigintToBytes32(chainId),
      addressToBytes32(wallet),
      s1,
      h1,
      s2,
      h2,
      bigintToBytes32(index),
      newSeed,
      newHash,
    ])
  );
}

export function upgradeDigest(
  wallet: Address,
  chainId: bigint,
  newImplementation: Address,
  s1: Hex,
  h1: Hex,
  s2: Hex,
  h2: Hex
): Hex {
  return keccak256(
    concat([
      UPGRADE_TAG,
      bigintToBytes32(chainId),
      addressToBytes32(wallet),
      addressToBytes32(newImplementation),
      s1,
      h1,
      s2,
      h2,
    ])
  );
}

export function verificationDigest(
  wallet: Address,
  chainId: bigint,
  newImplementation: Address,
  s1: Hex,
  h1: Hex
): Hex {
  return keccak256(
    concat([
      VERIFICATION_TAG,
      bigintToBytes32(chainId),
      addressToBytes32(wallet),
      addressToBytes32(newImplementation),
      s1,
      h1,
    ])
  );
}

export function upgradeRecoveryDigest(
  wallet: Address,
  chainId: bigint,
  newImplementation: Address,
  s1: Hex,
  h1: Hex,
  s2: Hex,
  h2: Hex
): Hex {
  return keccak256(
    concat([
      UPGRADE_RECOVERY_TAG,
      bigintToBytes32(chainId),
      addressToBytes32(wallet),
      addressToBytes32(newImplementation),
      s1,
      h1,
      s2,
      h2,
    ])
  );
}

export function erc4337ExecuteDigest(
  wallet: Address,
  chainId: bigint,
  s1: Hex,
  h1: Hex,
  s2: Hex,
  h2: Hex,
  userOpHash: Hex,
  fee: bigint
): Hex {
  return keccak256(
    concat([
      ERC4337_EXECUTE_TAG,
      bigintToBytes32(chainId),
      addressToBytes32(wallet),
      s1,
      h1,
      s2,
      h2,
      userOpHash,
      bigintToBytes32(fee),
    ])
  );
}

/// Commitment over the UserOp's constituent fields the paymaster signs.
/// Mirrors `QuipPaymaster._verifyAndRotate`:
///
///     opCommitment = keccak256(sender, nonce, keccak256(callData))
///
/// Constituent fields rather than `userOpHash` because `userOpHash`
/// includes `paymasterAndData` — which contains the paymaster signature
/// — creating a circular dependency.
export function paymasterOpCommitment(
  sender: Address,
  nonce: bigint,
  callData: Hex
): Hex {
  return keccak256(
    concat([
      addressToBytes32(sender),
      bigintToBytes32(nonce),
      keccak256(callData),
    ])
  );
}

/// Paymaster approval digest the WOTS+ verifier signs. Mirrors
/// `QuipPaymaster._verifyAndRotate`:
///
///     digest = keccak256(
///       PAYMASTER_APPROVE_TAG,
///       chainId,
///       paymaster,
///       currentVerifier.publicSeed, currentVerifier.publicKeyHash,
///       nextVerifier.publicSeed, nextVerifier.publicKeyHash,
///       paymasterOpCommitment(sender, nonce, callData)
///     )
export function paymasterUserOpDigest(
  paymaster: Address,
  chainId: bigint,
  currentVerifierSeed: Hex,
  currentVerifierHash: Hex,
  nextVerifierSeed: Hex,
  nextVerifierHash: Hex,
  sender: Address,
  nonce: bigint,
  callData: Hex
): Hex {
  const opCommitment = paymasterOpCommitment(sender, nonce, callData);
  return keccak256(
    concat([
      PAYMASTER_APPROVE_TAG,
      bigintToBytes32(chainId),
      addressToBytes32(paymaster),
      currentVerifierSeed,
      currentVerifierHash,
      nextVerifierSeed,
      nextVerifierHash,
      opCommitment,
    ])
  );
}

/// ERC-4337 v0.7 PackedUserOperation. Matches Solady's `ERC4337.sol:34` and
/// the canonical EntryPoint v0.7 layout. The two packed fields use the
/// EntryPoint v0.7 convention:
///   - `accountGasLimits` = `verificationGasLimit (uint128) || callGasLimit (uint128)`
///   - `gasFees`          = `maxPriorityFeePerGas (uint128) || maxFeePerGas (uint128)`
/// (high bytes first in each case)
export interface PackedUserOperation {
  sender: Address;
  nonce: bigint;
  initCode: Hex;
  callData: Hex;
  accountGasLimits: Hex; // bytes32
  preVerificationGas: bigint;
  gasFees: Hex; // bytes32
  paymasterAndData: Hex;
  signature: Hex;
}

/// Total `paymasterAndData` length the Quip paymaster expects:
///   52 (header: paymaster + verificationGasLimit + postOpGasLimit)
///   + 6 (validUntil) + 6 (validAfter)
///   + 64 (nextVerifier: publicSeed + publicKeyHash)
///   + 2144 (WOTS+ sig: 67 × 32)
///   = 2272
/// Mirrors `_PAYMASTER_AND_DATA_LEN` in `QuipPaymaster.sol:59`.
export const PAYMASTER_AND_DATA_LEN: number = 2272;

/// ERC-7201 namespace slot for `QuipPaymasterStorage.Layout`. Mirrors the
/// `_QUIP_PAYMASTER_STORAGE_SLOT` constant in
/// `contracts/storage/QuipPaymasterStorage.sol`:
///
///     keccak256(abi.encode(uint256(keccak256("quip.paymaster")) - 1))
///       & ~bytes32(uint256(0xff))
///
/// The `verifierKeyUsed` mapping is the second field in the struct, so its
/// base slot is `namespace + 1`.
export const PAYMASTER_STORAGE_NAMESPACE: Hex =
  "0x8926ce57d385a1d96a00d5ce1618d3e300ce201cbf2177f181835ec0ca228b00";

/// Pack two uint128 values into a bytes32 with the high 16 bytes being
/// `hi` and the low 16 bytes being `lo`. EntryPoint v0.7 uses this for
/// both `accountGasLimits` and `gasFees`.
export function packUint128Pair(hi: bigint, lo: bigint): Hex {
  if (hi < 0n || hi >= 1n << 128n) {
    throw new Error(`packUint128Pair: high value out of range: ${hi}`);
  }
  if (lo < 0n || lo >= 1n << 128n) {
    throw new Error(`packUint128Pair: low value out of range: ${lo}`);
  }
  const packed = (hi << 128n) | lo;
  return pad(toHex(packed), { size: 32 });
}

/// Convenience: pack (verificationGasLimit, callGasLimit) for `accountGasLimits`.
export function packAccountGasLimits(
  verificationGasLimit: bigint,
  callGasLimit: bigint
): Hex {
  return packUint128Pair(verificationGasLimit, callGasLimit);
}

/// Convenience: pack (maxPriorityFeePerGas, maxFeePerGas) for `gasFees`.
export function packGasFees(
  maxPriorityFeePerGas: bigint,
  maxFeePerGas: bigint
): Hex {
  return packUint128Pair(maxPriorityFeePerGas, maxFeePerGas);
}

/// Reverse of `packAccountGasLimits` for inspection. Returns
/// `{ verificationGasLimit, callGasLimit }`.
export function unpackAccountGasLimits(packed: Hex): {
  verificationGasLimit: bigint;
  callGasLimit: bigint;
} {
  if (size(packed) !== 32) {
    throw new Error(
      `unpackAccountGasLimits: expected 32 bytes, got ${size(packed)}`
    );
  }
  return {
    verificationGasLimit: hexToBigInt(slice(packed, 0, 16)),
    callGasLimit: hexToBigInt(slice(packed, 16, 32)),
  };
}

/// Reverse of `packGasFees` for inspection. Returns
/// `{ maxPriorityFeePerGas, maxFeePerGas }`.
export function unpackGasFees(packed: Hex): {
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
} {
  if (size(packed) !== 32) {
    throw new Error(`unpackGasFees: expected 32 bytes, got ${size(packed)}`);
  }
  return {
    maxPriorityFeePerGas: hexToBigInt(slice(packed, 0, 16)),
    maxFeePerGas: hexToBigInt(slice(packed, 16, 32)),
  };
}

/// Compute the EntryPoint v0.7 `userOpHash` locally — no RPC roundtrip.
/// Matches the reference implementation at
/// https://github.com/eth-infinitism/account-abstraction/blob/v0.7/contracts/core/UserOperationLib.sol
///
///     keccak256(abi.encode(hashUserOp(userOp), entryPoint, chainId))
///
/// where
///
///     hashUserOp(userOp) =
///       keccak256(abi.encode(
///         sender, nonce,
///         keccak256(initCode),
///         keccak256(callData),
///         accountGasLimits,
///         preVerificationGas,
///         gasFees,
///         keccak256(paymasterAndData)
///       ))
///
/// `signature` is excluded by design — it's what we're about to produce.
export function computeUserOpHash(
  userOp: PackedUserOperation,
  entryPoint: Address,
  chainId: bigint
): Hex {
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
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "address" }, { type: "uint256" }],
      [inner, entryPoint, chainId]
    )
  );
}

/// Construct the `paymasterAndData` field of a sponsored UserOp per the
/// Quip paymaster's layout (`QuipPaymaster.sol:52-59` + `INVARIANTS.md:229`):
///
///   [0:20)     paymaster address
///   [20:36)    validationGasLimit (uint128)
///   [36:52)    postOpGasLimit     (uint128)
///   [52:58)    validUntil         (uint48 / 6 bytes)
///   [58:64)    validAfter         (uint48 / 6 bytes)
///   [64:128)   nextVerifier       (publicSeed + publicKeyHash, 64 bytes)
///   [128:2272) WOTS+ signature    (67 × 32 = 2144 bytes)
///
/// `sig` defaults to all-zeros when omitted (used during digest
/// computation; substitute the real signature once it's produced).
export function packPaymasterAndData(params: {
  paymaster: Address;
  validationGasLimit: bigint;
  postOpGasLimit: bigint;
  validUntil: number; // uint48
  validAfter: number; // uint48
  nextVerifier: WinternitzAddress;
  sig?: WinternitzElements;
}): Hex {
  if (
    params.validationGasLimit < 0n ||
    params.validationGasLimit >= 1n << 128n
  ) {
    throw new Error(
      `packPaymasterAndData: validationGasLimit out of uint128 range: ${params.validationGasLimit}`
    );
  }
  if (params.postOpGasLimit < 0n || params.postOpGasLimit >= 1n << 128n) {
    throw new Error(
      `packPaymasterAndData: postOpGasLimit out of uint128 range: ${params.postOpGasLimit}`
    );
  }
  if (params.validUntil < 0 || params.validUntil >= 2 ** 48) {
    throw new Error(
      `packPaymasterAndData: validUntil out of uint48 range: ${params.validUntil}`
    );
  }
  if (params.validAfter < 0 || params.validAfter >= 2 ** 48) {
    throw new Error(
      `packPaymasterAndData: validAfter out of uint48 range: ${params.validAfter}`
    );
  }

  const sigHex =
    params.sig !== undefined
      ? concat(params.sig.elements)
      : (("0x" + "00".repeat(67 * 32)) as Hex);

  const validationGasLimitHex = pad(toHex(params.validationGasLimit), {
    size: 16,
  });
  const postOpGasLimitHex = pad(toHex(params.postOpGasLimit), { size: 16 });
  const validUntilHex = pad(toHex(BigInt(params.validUntil)), { size: 6 });
  const validAfterHex = pad(toHex(BigInt(params.validAfter)), { size: 6 });

  return concat([
    params.paymaster,
    validationGasLimitHex,
    postOpGasLimitHex,
    validUntilHex,
    validAfterHex,
    params.nextVerifier.publicSeed,
    params.nextVerifier.publicKeyHash,
    sigHex,
  ]);
}

/// Decode a `paymasterAndData` field back into its constituent parts.
/// Inverse of `packPaymasterAndData`. Throws on length mismatch (the
/// paymaster rejects any other length on chain).
export function decodePaymasterAndData(pmd: Hex): {
  paymaster: Address;
  validationGasLimit: bigint;
  postOpGasLimit: bigint;
  validUntil: number;
  validAfter: number;
  nextVerifier: WinternitzAddress;
  sig: WinternitzElements;
} {
  if (size(pmd) !== PAYMASTER_AND_DATA_LEN) {
    throw new Error(
      `decodePaymasterAndData: expected ${PAYMASTER_AND_DATA_LEN} bytes, got ${size(pmd)}`
    );
  }
  return {
    paymaster: getAddress(slice(pmd, 0, 20)),
    validationGasLimit: hexToBigInt(slice(pmd, 20, 36)),
    postOpGasLimit: hexToBigInt(slice(pmd, 36, 52)),
    validUntil: Number(hexToBigInt(slice(pmd, 52, 58))),
    validAfter: Number(hexToBigInt(slice(pmd, 58, 64))),
    nextVerifier: sliceAddress(pmd, 64),
    sig: sliceElements(pmd, 128),
  };
}

/// Hash a verifier key the way the paymaster does: `keccak256(publicSeed || publicKeyHash)`.
/// Mirrors `QuipPaymaster._verifierHash` (which calls `EfficientHashLib.hash`,
/// equivalent to a plain keccak over the concatenation).
export function paymasterVerifierHash(verifier: WinternitzAddress): Hex {
  return keccak256(concat([verifier.publicSeed, verifier.publicKeyHash]));
}

/// Storage slot of `verifierKeyUsed[verifierHash]` in the paymaster's
/// ERC-7201 namespaced storage. Used by simulators / observers that want
/// to detect whether a verifier key has been spent without an extra RPC
/// roundtrip into a paymaster view.
///
/// `verifierKeyUsed` is the second field of `QuipPaymasterStorage.Layout`,
/// so its mapping base lives at `PAYMASTER_STORAGE_NAMESPACE + 1`. The
/// per-key slot is `keccak256(key || baseSlot)`, per Solidity's standard
/// mapping layout.
export function paymasterVerifierKeyUsedSlot(
  verifier: WinternitzAddress
): Hex {
  const verifierHash = paymasterVerifierHash(verifier);
  const baseSlot = toHex(BigInt(PAYMASTER_STORAGE_NAMESPACE) + 1n, {
    size: 32,
  });
  return keccak256(concat([verifierHash, baseSlot]));
}
