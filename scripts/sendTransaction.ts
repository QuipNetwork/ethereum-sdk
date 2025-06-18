import { ethers } from "ethers";

interface TransactionData {
  from: string;
  to: string;
  data: string;
  value: string;
  gas: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
  gasPrice?: string;
  nonce: string;
  chainId?: number;
}

async function sendTransaction(txData: string): Promise<void> {
  try {
    const provider = new ethers.JsonRpcProvider("http://localhost:8545");
    const privateKey = process.env.PRIVATE_KEY;

    if (!privateKey) {
      throw new Error("PRIVATE_KEY environment variable not set");
    }

    const wallet = new ethers.Wallet(privateKey, provider);

    // Parse the transaction data
    const txDataParsed: TransactionData = JSON.parse(txData);

    // Convert nonce to number for ethers.js
    const tx = {
      ...txDataParsed,
      nonce: parseInt(txDataParsed.nonce, 16),
    };

    // Send the transaction
    const txResponse = await wallet.sendTransaction(tx);
    console.log(txResponse.hash);

    // Wait for the transaction to be mined
    const receipt = await txResponse.wait();

    // Return the wallet address from the QuipCreated event
    if (receipt && receipt.logs && receipt.logs.length > 0) {
      const eventData = receipt.logs[0].data;
      const walletAddress = "0x" + eventData.slice(-40);
      console.log(walletAddress);
    } else {
      throw new Error("No logs found in transaction receipt");
    }
  } catch (error) {
    console.error(
      "Error:",
      error instanceof Error ? error.message : String(error)
    );
    process.exit(1);
  }
}

// Get transaction data from command line argument
const txData = process.argv[2];
if (!txData) {
  console.error("Usage: npx ts-node send_transaction.ts <transaction_json>");
  process.exit(1);
}

sendTransaction(txData);
