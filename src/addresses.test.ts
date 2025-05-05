import { getVaultAddress, computeVaultAddress } from './addresses';

describe('Vault Address Functions', () => {
  const testVaultId = '0x783e1393edc4a6dac846b6da7723acb50de92b51b66ccdbc69bcadfb3fd9da69';
  const testOwner = '0x4971905b8741bdbe1ba008f73c28c82de9d95df9';
  
  it('should compute the correct vault address', () => {
    // Expected address from the transaction
    const expectedAddress = '0x3Afa8a2ccE74AF1C6b0BE711f19C1517e0a47857';
    
    // Compute address using our function
    const address = getVaultAddress(testOwner, testVaultId);
    
    // Verify it matches the expected address
    expect(address.toLowerCase()).toEqual(expectedAddress.toLowerCase());
    
    // Log the computed address for verification
    console.log(`GET vault address: ${address}`);
  });

  it('should compute the same address with computeVaultAddress', () => {
    // Get addresses from the module
    const { WOTS_PLUS_ADDRESS, QUIP_FACTORY_ADDRESS } = require('./addresses');
    
    const address1 = getVaultAddress(testOwner, testVaultId);
    const address2 = computeVaultAddress(
      testOwner,
      testVaultId,
      WOTS_PLUS_ADDRESS,
      QUIP_FACTORY_ADDRESS
    );
    
    // Both functions should return the same address
    expect(address1).toEqual(address2);
  });
});
