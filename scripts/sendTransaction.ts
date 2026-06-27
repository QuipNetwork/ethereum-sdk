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
    const rpcUrl = 'http://localhost:8545';
    const provider = new ethers.JsonRpcProvider(rpcUrl);
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
    console.log('Transaction hash:', txResponse.hash);
    
    try {
      // Wait for the transaction to be mined
      const receipt = await txResponse.wait();
      
      // Return the wallet address from the QuipCreated event
      if (receipt && receipt.logs && receipt.logs.length > 0) {
        const eventData = receipt.logs[0].data;
        const walletAddress = '0x' + eventData.slice(-40);
        console.log(walletAddress);
      } else {
        console.warn('Warning: No transaction logs were found which may indicate a success or a failure depending on the transaction type. Please look for additional logs.');
        console.log('Transaction mined with status:', receipt?.status);
      }
    } catch (error: any) {
      // Print detailed error information for debugging
      console.error('Transaction failed!');
      console.error('Raw error:', error);
      if (error.reason) {
        console.error('Revert reason:', error.reason);
      }
      if (error.data) {
        console.error('Error data:', error.data);
      }
      if (error.error && error.error.body) {
        try {
          const body = JSON.parse(error.error.body);
          if (body && body.error && body.error.message) {
            console.error('Error message:', body.error.message);
          }
        } catch (e) {}
      }
      // Call printTxReceipt.ts with the transaction hash and RPC URL
      const { spawnSync } = require('child_process');
      const receiptResult = spawnSync('npx', ['ts-node', require('path').join(__dirname, 'printTxReceipt.ts'), txResponse.hash, rpcUrl], { stdio: 'inherit' });
      if (receiptResult.error) {
        console.error('Failed to print transaction receipt:', receiptResult.error);
      }
      process.exit(1);
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
