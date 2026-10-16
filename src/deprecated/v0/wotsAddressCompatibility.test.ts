// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Cross-chain address-compatibility guard for legacy WOTS+ wallets.
//
// The original QuipFactory (src/deprecated/v0) deploys each wallet with CREATE2, so
// the wallet address is f(QuipFactory, vaultId, keccak256(initcode)). The V1
// WalletFactory (src/v1) deploys with CREATE3 — f(WalletFactory, salt), independent
// of initcode and rooted at a different deployer contract. The two address spaces are
// therefore disjoint: a WOTS+ wallet the original factory placed on one chain can only
// be reproduced on another chain by the SAME original QuipFactory, never by the V1
// factory. This test pins that fact so a future change cannot silently route legacy
// WOTS+ deploys through the V1 factory and orphan every already-deployed wallet.

import { getAddress, keccak256 } from "viem";

import {
  computeVaultAddress,
  QUIP_FACTORY_ADDRESS,
  WOTS_PLUS_ADDRESS,
} from "./addresses.js";
import {
  computeCreate3Address,
  getNetworkAddresses as getV1NetworkAddresses,
} from "../../v1/addresses.js";

describe("legacy WOTS+ cross-chain address compatibility", () => {
  // A fixed identity for the golden vector.
  const OWNER = "0x00000000000000000000000000000000000000AA";
  const VAULT_ID =
    "0x0000000000000000000000000000000000000000000000000000000000000001";

  // The deterministic address the ORIGINAL QuipFactory (CREATE2) produces for this
  // identity at the shared factory 0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99. This is
  // the address that already exists on every chain the original factory was deployed to.
  const GOLDEN_ORIGINAL_VAULT = getAddress(
    "0x9c1314Bb834Ab529BB18F94C65b5A8d3b98DaAc2"
  );

  it("original QuipFactory reproduces the golden CREATE2 vault address", () => {
    const addr = computeVaultAddress(
      OWNER,
      VAULT_ID,
      WOTS_PLUS_ADDRESS,
      QUIP_FACTORY_ADDRESS
    );
    expect(getAddress(addr)).toBe(GOLDEN_ORIGINAL_VAULT);
  });

  it("the V1 WalletFactory (CREATE3) cannot reproduce the original address", () => {
    const walletFactory = getV1NetworkAddresses().WalletFactory;
    // Try the plausible salt conventions a V1 deploy would use for this vaultId. None
    // can equal the original CREATE2 address: the deployer and the derivation differ.
    const asRawSalt = computeCreate3Address(walletFactory, VAULT_ID);
    const asHashedSalt = computeCreate3Address(
      walletFactory,
      keccak256(VAULT_ID)
    );
    expect(getAddress(asRawSalt)).not.toBe(GOLDEN_ORIGINAL_VAULT);
    expect(getAddress(asHashedSalt)).not.toBe(GOLDEN_ORIGINAL_VAULT);
  });
});
