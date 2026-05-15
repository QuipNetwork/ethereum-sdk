import { type Address, type Hex } from "viem";
import {
  CHAIN_IDS,
  getNetworkAddresses,
  getVaultAddress,
  computeVaultAddress,
  QUIP_FACTORY_ADDRESS,
} from "../addresses.js";
import { UnsupportedNetworkError } from "../errors.js";

describe("Vault Address Functions", () => {
  const testVaultId: Hex =
    "0x783e1393edc4a6dac846b6da7723acb50de92b51b66ccdbc69bcadfb3fd9da69";

  // Known-good CREATE3 address for (QUIP_FACTORY_ADDRESS, testVaultId),
  // verified against Solady CREATE3.deployDeterministic.
  const expectedAddress: Address =
    "0xB0AA5b33a205C8FE16409743e9b3d4428E1359E4";

  it("should return the expected CREATE3 address", () => {
    expect(getVaultAddress(testVaultId)).toEqual(expectedAddress);
  });

  it("should match between getVaultAddress and computeVaultAddress", () => {
    const fromGet = getVaultAddress(testVaultId);
    const fromCompute = computeVaultAddress(QUIP_FACTORY_ADDRESS, testVaultId);
    expect(fromGet).toEqual(fromCompute);
  });
});

describe("getNetworkAddresses", () => {
  it("returns default addresses when chainId is omitted", () => {
    const addrs = getNetworkAddresses();
    expect(addrs.QuipFactory).toEqual(QUIP_FACTORY_ADDRESS);
  });

  it("returns the registered entry for chains explicitly listed in NETWORK_ADDRESSES (MIDL)", () => {
    const addrs = getNetworkAddresses(CHAIN_IDS.MIDL_TESTNET);
    // MIDL is registered but currently zero-addressed until deployment.
    expect(addrs.QuipFactory).toEqual(
      "0x0000000000000000000000000000000000000000"
    );
  });

  it("returns default addresses for shared CREATE2 chains (mainnet / sepolia / base / op)", () => {
    for (const chainId of [
      CHAIN_IDS.ETHEREUM_MAINNET,
      CHAIN_IDS.SEPOLIA,
      CHAIN_IDS.BASE,
      CHAIN_IDS.BASE_SEPOLIA,
      CHAIN_IDS.OPTIMISM,
      CHAIN_IDS.OPTIMISM_SEPOLIA,
    ]) {
      const addrs = getNetworkAddresses(chainId);
      expect(addrs.QuipFactory).toEqual(QUIP_FACTORY_ADDRESS);
    }
  });

  it("throws UnsupportedNetworkError for chains outside the supported set", () => {
    expect(() => getNetworkAddresses(424242)).toThrow(UnsupportedNetworkError);
  });

  it("UnsupportedNetworkError carries the offending chainId", () => {
    try {
      getNetworkAddresses(424242);
      fail("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(UnsupportedNetworkError);
      expect((e as UnsupportedNetworkError).chainId).toEqual(424242);
    }
  });
});
