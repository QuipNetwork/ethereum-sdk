import { type Address, type Hex } from "viem";
import {
  getVaultAddress,
  computeVaultAddress,
  QUIP_FACTORY_ADDRESS,
} from "./addresses.js";

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
