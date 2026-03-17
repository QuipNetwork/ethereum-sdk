import {
  type Address,
  type Hex,
  getCreate2Address,
  keccak256,
  concat,
  encodeAbiParameters,
} from "viem";
import {
  getVaultAddress,
  computeVaultAddress,
  WOTS_PLUS_ADDRESS,
  QUIP_FACTORY_ADDRESS,
} from "./addresses.js";
import bytecodeData from "./bytecode.json" with { type: "json" };

describe("Vault Address Functions", () => {
  const testVaultId: Hex =
    "0x783e1393edc4a6dac846b6da7723acb50de92b51b66ccdbc69bcadfb3fd9da69";
  const testOwner: Address = "0x4971905b8741bdbe1ba008f73c28c82de9d95df9";

  it("should match viem getCreate2Address", () => {
    const initCode = concat([
      bytecodeData.quipWalletCreationCode as Hex,
      encodeAbiParameters(
        [{ type: "address" }, { type: "address" }],
        [QUIP_FACTORY_ADDRESS, testOwner]
      ),
    ]);

    const expected = getCreate2Address({
      from: QUIP_FACTORY_ADDRESS,
      salt: testVaultId,
      bytecodeHash: keccak256(initCode),
    });

    const address = getVaultAddress(testOwner, testVaultId);
    expect(address).toEqual(expected);
  });

  it("should compute the same address with computeVaultAddress", () => {
    const address1 = getVaultAddress(testOwner, testVaultId);
    const address2 = computeVaultAddress(
      testOwner,
      testVaultId,
      WOTS_PLUS_ADDRESS,
      QUIP_FACTORY_ADDRESS
    );

    expect(address1).toEqual(address2);
  });
});
