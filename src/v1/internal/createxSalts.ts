// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Sender-guarded CreateX CREATE3 derivation — the ONE TypeScript implementation.
 *
 * Mirrors `script/CreateXHelpers.sol` and `script/Constants.sol`. Consumed by
 * `scripts/release.ts` (which writes the SDK address registry) and by
 * `src/v1/shrincs/tests/addresses.test.ts` (which re-derives the published
 * addresses and asserts they match what the SDK ships). Keeping it in one place
 * is deliberate: a second copy of the guard formula that goes stale still
 * computes *an* address, and the assertion against it still passes.
 *
 *   rawSalt     = bytes20(operator) ‖ 0x00 ‖ bytes11(keccak256(preimage))
 *   guardedSalt = keccak256(bytes32(uint160(operator)) ‖ rawSalt)
 *   address     = CREATE3(CreateX, guardedSalt)
 *
 * Byte 20 is CreateX's cross-chain flag: 0x01 folds `block.chainid` into the
 * guard (per-chain addresses), 0x00 leaves it out (identical addresses on every
 * chain). We always want 0x00 — `senderGuardedRawSalt` writes it explicitly and
 * `assertSaltLayout` refuses anything else.
 *
 * NOTE the CreateX API asymmetry: `deployCreate3` consumes the RAW salt (and
 * guards internally); address prediction consumes the GUARDED salt.
 */

import {
  concatHex,
  encodeAbiParameters,
  getAddress,
  getContractAddress,
  getCreate2Address,
  keccak256,
  padHex,
  toHex,
  type Address,
  type Hex,
} from "viem";

/// Canonical CreateX singleton (github.com/pcaversaccio/createx), pre-deployed
/// at the same address on every supported chain.
export const CREATEX_ADDRESS: Address = getAddress(
  "0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed",
);

/// The one account every live canonical address derives from. Mirrors
/// `DeployConstants.CANONICAL_OPERATOR`; changing it re-derives EVERY live
/// address, so the two must move together.
export const CANONICAL_OPERATOR: Address = getAddress(
  "0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26",
);

/// Solady CREATE3 proxy initcode hash: keccak256(hex"67363d3d37363d34f03d5260086018f3").
/// CreateX uses the same proxy initcode, so solady's predictor works against it.
export const PROXY_INITCODE_HASH: Hex =
  "0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f";

/// The verifier scheme tag the two IMPLEMENTATION salts bind, so an impl built
/// against a different cryptographic scheme lands at a different address.
/// Equals the deployed verifier's `PROFILE_TAG()`.
export const SHRINCS_PROFILE_ID: Hex = keccak256(toHex("shrincs-256s-keccak"));

/// Live salt preimages — mirror `script/Constants.sol` exactly. The wallet and
/// the paymaster version independently; the strings are opaque, so only
/// uniqueness matters (`V1.0.1-beta` is NOT "newer than" `V1.1`).
export const LIVE_SALT_PREIMAGES = {
  WalletFactoryImpl: toHex("QUIP:WalletFactory:Impl:V1.0.0-beta"),
  WalletFactoryProxy: toHex("QUIP:WalletFactory:Proxy:V1.0.0-beta"),
  ShrincsWalletImplementation: concatHex([
    toHex("QUIP:ShrincsWallet:V1.1:"),
    SHRINCS_PROFILE_ID,
  ]),
  ShrincsPaymasterImpl: concatHex([
    toHex("QUIP:ShrincsPaymaster:Impl:V1.0.1-beta:"),
    SHRINCS_PROFILE_ID,
  ]),
  ShrincsPaymasterProxy: toHex("QUIP:ShrincsPaymaster:Proxy:V1.0.1-beta"),
} as const;

/// CREATE3: CREATE2 the proxy, then the child at the proxy's nonce 1.
export function computeCreate3Address(deployer: Address, salt: Hex): Address {
  const proxy = getCreate2Address({
    from: deployer,
    salt,
    bytecodeHash: PROXY_INITCODE_HASH,
  });
  return getContractAddress({ from: proxy, nonce: 1n });
}

/// `bytes20(operator) ‖ 0x00 ‖ bytes11(keccak256(preimage))`. The `00` is the
/// cross-chain flag, written explicitly rather than left as an unfilled gap.
export function senderGuardedRawSalt(operator: Address, preimage: Hex): Hex {
  const entropy11 = keccak256(preimage).slice(2, 2 + 22);
  const salt = `0x${operator.slice(2).toLowerCase()}00${entropy11}` as Hex;
  assertSaltLayout(operator, salt);
  return salt;
}

/// Fail closed on the two properties CreateX branches on. Neither can be wrong
/// by construction today; this exists because taking the wrong branch does not
/// throw inside CreateX — it deploys successfully, at a different address.
export function assertSaltLayout(operator: Address, rawSalt: Hex): void {
  const body = rawSalt.slice(2);
  if (body.length !== 64) {
    throw new Error(`raw salt must be 32 bytes, got ${body.length / 2}`);
  }
  if (body.slice(0, 40) !== operator.slice(2).toLowerCase()) {
    throw new Error(
      "salt layout: bytes 0-19 are not the operator (CreateX would take the permissionless branch)",
    );
  }
  if (body.slice(40, 42) !== "00") {
    throw new Error(
      "salt layout: byte 20 is not 0x00 (CreateX would bind block.chainid and break chain-invariance)",
    );
  }
}

/// CreateX's MsgSender + no-crosschain guard branch.
export function senderGuardedSalt(operator: Address, rawSalt: Hex): Hex {
  return keccak256(concatHex([padHex(operator, { size: 32 }), rawSalt]));
}

/// The canonical address for (operator, preimage).
export function senderGuardedAddress(
  operator: Address,
  preimage: Hex,
): Address {
  return computeCreate3Address(
    CREATEX_ADDRESS,
    senderGuardedSalt(operator, senderGuardedRawSalt(operator, preimage)),
  );
}

/// Where the SAME salt resolves on CreateX's PERMISSIONLESS branch —
/// `guardedSalt = keccak256(abi.encode(salt))` — i.e. where a non-operator
/// caller lands. Must never coincide with `senderGuardedAddress`.
export function permissionlessAddress(
  operator: Address,
  preimage: Hex,
): Address {
  const rawSalt = senderGuardedRawSalt(operator, preimage);
  return computeCreate3Address(
    CREATEX_ADDRESS,
    keccak256(encodeAbiParameters([{ type: "bytes32" }], [rawSalt])),
  );
}
