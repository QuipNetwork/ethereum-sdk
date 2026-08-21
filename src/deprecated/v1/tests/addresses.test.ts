import { type Address, type Hex } from "viem";
import {
  CHAIN_IDS,
  NETWORK_ADDRESSES,
  getNetworkAddresses,
  getVaultAddress,
  computeVaultAddress,
} from "../../../v1/addresses.js";
import { UnsupportedNetworkError } from "../errors.js";

const defaultFactory = NETWORK_ADDRESSES.default.WalletFactory;

describe("Vault Address Functions", () => {
  const testVaultId: Hex =
    "0x783e1393edc4a6dac846b6da7723acb50de92b51b66ccdbc69bcadfb3fd9da69";

  // Known-good CREATE3 address for (default WalletFactory, testVaultId).
  // Updated for the CreateX-era WalletFactory proxy (0x6de121F7…, the
  // v1.1 0xd175… lineage was abandoned pre-launch with nothing deployed),
  // independently re-derived:
  //   proxy = create2(factory, vaultId, keccak256(0x67363d3d37363d34f03d5260086018f3))
  //   vault = keccak256(0xd694 ++ proxy ++ 0x01)[12:]
  // Re-derive the same way if the factory address or testVaultId change again.
  const expectedAddress: Address =
    "0x800C361A4cADf163d2e1C992fAA8BA77e52619c8";

  it("should return the expected CREATE3 address", () => {
    expect(getVaultAddress(testVaultId)).toEqual(expectedAddress);
  });

  it("should match between getVaultAddress and computeVaultAddress", () => {
    const fromGet = getVaultAddress(testVaultId);
    const fromCompute = computeVaultAddress(defaultFactory, testVaultId);
    expect(fromGet).toEqual(fromCompute);
  });
});

describe("getNetworkAddresses", () => {
  it("returns default addresses when chainId is omitted", () => {
    const addrs = getNetworkAddresses();
    expect(addrs.WalletFactory).toEqual(defaultFactory);
  });

  it("returns the registered entry for chains explicitly listed in NETWORK_ADDRESSES (MIDL)", () => {
    const addrs = getNetworkAddresses(CHAIN_IDS.MIDL_TESTNET);
    expect(addrs).toBe(NETWORK_ADDRESSES[CHAIN_IDS.MIDL_TESTNET]);
    expect(addrs.WalletFactory).toEqual(
      NETWORK_ADDRESSES[CHAIN_IDS.MIDL_TESTNET].WalletFactory
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
      expect(addrs.WalletFactory).toEqual(defaultFactory);
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
