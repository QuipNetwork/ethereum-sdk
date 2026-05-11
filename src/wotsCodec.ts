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
