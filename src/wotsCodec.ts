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
  getAddress,
  hexToBigInt,
  keccak256,
  pad,
  size,
  slice,
  toHex,
} from "viem";

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                           TYPES                               */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

export interface WinternitzAddress {
  publicSeed: Hex;
  publicKeyHash: Hex;
}

export interface WinternitzElements {
  elements: Hex[];
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                         CONSTANTS                             */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

export const WOTS_ADDRESS_SIZE = 64;
export const WOTS_ELEMENTS_SIZE = 2144;
export const WOTS_ELEMENTS_COUNT = 67;
export const RECOVERY_KEY_AMOUNT = 10;

export const KEY_ROTATION_TAG: Hex = keccak256(toHex("quip.digest.keyRotation"));
export const EXECUTE_TAG: Hex = keccak256(toHex("quip.digest.execute"));
export const KEY_MGMT_TAG: Hex = keccak256(toHex("quip.digest.keyManagement"));
export const UPGRADE_TAG: Hex = keccak256(toHex("quip.digest.upgrade"));
export const VERIFICATION_TAG: Hex = keccak256(toHex("quip.digest.verification"));

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                          HELPERS                              */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

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

function bigintToBytes32(value: bigint): Hex {
  return toHex(value, { size: 32 });
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                          ENCODERS                             */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

export function encodeInit(
  pqOwner: WinternitzAddress,
  recoveryKeys: WinternitzAddress[],
): Hex {
  return concat([
    packAddress(pqOwner),
    ...recoveryKeys.map(packAddress),
  ]);
}

export function encodeChangePqOwner(
  newPqOwner: WinternitzAddress,
  pqSig: WinternitzElements,
): Hex {
  return concat([
    packAddress(newPqOwner),
    packElements(pqSig),
  ]);
}

export function encodeExecute(
  nextPqOwner: WinternitzAddress,
  pqSig: WinternitzElements,
  target: Address,
  value: bigint,
  data: Hex = "0x",
): Hex {
  return concat([
    packAddress(nextPqOwner),
    packElements(pqSig),
    addressToBytes32(target),
    bigintToBytes32(value),
    data,
  ]);
}

export function encodeRecoverWallet(
  recoveryKey: WinternitzAddress,
  newPqOwner: WinternitzAddress,
  pqSig: WinternitzElements,
): Hex {
  return concat([
    packAddress(recoveryKey),
    packAddress(newPqOwner),
    packElements(pqSig),
  ]);
}

export function encodeKeyManagement(
  nextPqOwner: WinternitzAddress,
  pqSig: WinternitzElements,
  newRecoveryKeys: WinternitzAddress[],
): Hex {
  return concat([
    packAddress(nextPqOwner),
    packElements(pqSig),
    ...newRecoveryKeys.map(packAddress),
  ]);
}

export function encodeUpgrade(
  nextPqOwner: WinternitzAddress,
  pqSig: WinternitzElements,
  verifier: WinternitzAddress,
  verifySig: WinternitzElements,
  shouldMigrate: boolean,
  migratorPayload: Hex,
): Hex {
  return concat([
    packAddress(nextPqOwner),
    packElements(pqSig),
    packAddress(verifier),
    packElements(verifySig),
    shouldMigrate ? "0x01" : "0x00",
    migratorPayload,
  ]);
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                          DECODERS                             */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

export function decodeInit(payload: Hex): {
  pqOwner: WinternitzAddress;
  recoveryKeys: WinternitzAddress[];
} {
  const pqOwner = sliceAddress(payload, 0);
  const recoveryKeys: WinternitzAddress[] = [];
  for (let i = 0; i < RECOVERY_KEY_AMOUNT; i++) {
    recoveryKeys.push(sliceAddress(payload, 64 + i * 64));
  }
  return { pqOwner, recoveryKeys };
}

export function decodeUpgradeAuth(data: Hex): {
  nextPqOwner: WinternitzAddress;
  pqSig: WinternitzElements;
} {
  return {
    nextPqOwner: sliceAddress(data, 0),
    pqSig: sliceElements(data, 64),
  };
}

export function decodeUpgradeVerification(data: Hex): {
  verifier: WinternitzAddress;
  verifySig: WinternitzElements;
} {
  return {
    verifier: sliceAddress(data, 2208),
    verifySig: sliceElements(data, 2272),
  };
}

export function decodeUpgradeMigration(data: Hex): {
  shouldMigrate: boolean;
  migratorPayload: Hex;
} {
  return {
    shouldMigrate: slice(data, 4416, 4417) !== "0x00",
    migratorPayload: slice(data, 4417, 5121),
  };
}

export function decodeChangePqOwner(payload: Hex): {
  newPqOwner: WinternitzAddress;
  pqSig: WinternitzElements;
} {
  return {
    newPqOwner: sliceAddress(payload, 0),
    pqSig: sliceElements(payload, 64),
  };
}

export function decodeExecute(payload: Hex): {
  nextPqOwner: WinternitzAddress;
  pqSig: WinternitzElements;
  target: Address;
  value: bigint;
  data: Hex;
} {
  return {
    nextPqOwner: sliceAddress(payload, 0),
    pqSig: sliceElements(payload, 64),
    target: getAddress(slice(payload, 2220, 2240)),
    value: hexToBigInt(slice(payload, 2240, 2272)),
    data: size(payload) > 2272 ? slice(payload, 2272) : "0x",
  };
}

export function decodeRecoverWallet(payload: Hex): {
  recoveryKey: WinternitzAddress;
  newPqOwner: WinternitzAddress;
  pqSig: WinternitzElements;
} {
  return {
    recoveryKey: sliceAddress(payload, 0),
    newPqOwner: sliceAddress(payload, 64),
    pqSig: sliceElements(payload, 128),
  };
}

export function decodeKeyManagement(payload: Hex): {
  nextPqOwner: WinternitzAddress;
  pqSig: WinternitzElements;
  newRecoveryKeys: WinternitzAddress[];
} {
  const payloadSize = size(payload);
  const keyCount = (payloadSize - 2208) / 64;
  const newRecoveryKeys: WinternitzAddress[] = [];
  for (let i = 0; i < keyCount; i++) {
    newRecoveryKeys.push(sliceAddress(payload, 2208 + i * 64));
  }
  return {
    nextPqOwner: sliceAddress(payload, 0),
    pqSig: sliceElements(payload, 64),
    newRecoveryKeys,
  };
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                          DIGESTS                              */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

export function keyRotationDigest(
  wallet: Address,
  chainId: bigint,
  s1: Hex,
  h1: Hex,
  s2: Hex,
  h2: Hex,
): Hex {
  return keccak256(concat([
    KEY_ROTATION_TAG,
    bigintToBytes32(chainId),
    addressToBytes32(wallet),
    s1, h1, s2, h2,
  ]));
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
): Hex {
  return keccak256(concat([
    EXECUTE_TAG,
    bigintToBytes32(chainId),
    addressToBytes32(wallet),
    s1, h1, s2, h2,
    addressToBytes32(target),
    bigintToBytes32(value),
    opdataHash,
  ]));
}

export function keyManagementDigest(
  wallet: Address,
  chainId: bigint,
  s1: Hex,
  h1: Hex,
  s2: Hex,
  h2: Hex,
  keysHash: Hex,
): Hex {
  return keccak256(concat([
    KEY_MGMT_TAG,
    bigintToBytes32(chainId),
    addressToBytes32(wallet),
    s1, h1, s2, h2,
    keysHash,
  ]));
}

export function upgradeDigest(
  wallet: Address,
  chainId: bigint,
  newImplementation: Address,
  s1: Hex,
  h1: Hex,
  s2: Hex,
  h2: Hex,
): Hex {
  return keccak256(concat([
    UPGRADE_TAG,
    bigintToBytes32(chainId),
    addressToBytes32(wallet),
    addressToBytes32(newImplementation),
    s1, h1, s2, h2,
  ]));
}

export function verificationDigest(
  wallet: Address,
  chainId: bigint,
  newImplementation: Address,
  s1: Hex,
  h1: Hex,
): Hex {
  return keccak256(concat([
    VERIFICATION_TAG,
    bigintToBytes32(chainId),
    addressToBytes32(wallet),
    addressToBytes32(newImplementation),
    s1, h1,
  ]));
}
