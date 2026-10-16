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

/// Signature-scheme-agnostic ERC-4337 v0.7 codec helpers, shared by every
/// wallet family. Extracted from the (now deprecated) WOTS+ codec — the
/// PackedUserOperation layout, gas-field packing, and the canonical
/// EntryPoint v0.7 userOpHash have nothing WOTS-specific about them.
import {
  type Address,
  type Hex,
  encodeAbiParameters,
  hexToBigInt,
  keccak256,
  pad,
  size,
  slice,
  toHex,
} from "viem";

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
