#!/usr/bin/env ts-node

// Usage: ts-node abi_encode.ts <abi_json> <function_name> <params_json>
// Example: ts-node abi_encode.ts '[{"inputs":[...]}]' 'depositToWinternitz' '[{"vaultId":"0x...","to":"0x...","pqTo":{"publicSeed":"0x...","publicKeyHash":"0x..."}}]'

import { ethers } from "ethers";

if (process.argv.length < 5) {
  console.error("Usage: ts-node abi_encode.ts <abi_json> <function_name> <params_json>");
  console.error("Example: ts-node abi_encode.ts '[{\"inputs\":[...]}]' 'depositToWinternitz' '[{\"vaultId\":\"0x...\",\"to\":\"0x...\",\"pqTo\":{\"publicSeed\":\"0x...\",\"publicKeyHash\":\"0x...\"}}]'");
  process.exit(1);
}

try {
  const abi = JSON.parse(process.argv[2]);
  const fn = process.argv[3];
  const params = JSON.parse(process.argv[4]);

  const iface = new ethers.Interface(abi);
  const data = iface.encodeFunctionData(fn, params);
  console.log(data);
} catch (error: any) {
  console.error("Error encoding ABI:", error.message);
  process.exit(1);
} 