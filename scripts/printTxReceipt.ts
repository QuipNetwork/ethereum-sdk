#!/usr/bin/env ts-node
import { ethers } from "ethers";

async function main() {
  const [txHash, rpcUrl] = process.argv.slice(2);
  if (!txHash || !rpcUrl) {
    console.error("Usage: printTxReceipt.ts <txHash> <rpcUrl>");
    process.exit(1);
  }
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  try {
    const receipt = await provider.getTransactionReceipt(txHash);
    if (!receipt) {
      console.error("No receipt found for transaction:", txHash);
      process.exit(1);
    }
    console.log("\n=== Transaction Receipt ===");
    console.log(JSON.stringify(receipt, null, 2));
    if (receipt.status === 0) {
      // Try to get revert reason
      const tx = await provider.getTransaction(txHash);
      if (tx) {
        try {
          await provider.call({ ...tx, from: tx.from, blockTag: receipt.blockNumber });
        } catch (err: any) {
          const match = /revert(?:ed)?(?: with reason string)?(?: ')?([^']*)/.exec(err.message);
          if (match && match[1]) {
            console.log("\nRevert reason:", match[1]);
          } else {
            console.log("\nRevert error:", err.message);
          }
        }
      }
    }
  } catch (err) {
    console.error("Error fetching transaction receipt:", err);
    process.exit(1);
  }
}

main(); 