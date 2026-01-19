// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Balance Checker
 *
 * Displays account balances in a table format for both EVM and MIDL networks.
 * Shows Deployer and Operations wallets, plus any additional addresses.
 *
 * For MIDL networks, both BTC and EVM balances are displayed.
 *
 * Usage:
 *   # Show deployer and operations balances
 *   npx hardhat run scripts/balance.cts --network sepolia
 *
 *   # With additional addresses (comma-separated)
 *   ADDRESSES=0x1234...,0xabcd... npx hardhat run scripts/balance.cts --network sepolia
 *
 *   # MIDL with BTC address
 *   ADDRESSES=bcrt1q... npx hardhat run scripts/balance.cts --network midl_regtest
 *
 *   # With private key (derives address)
 *   ADDRESSES=0x123...64chars... npx hardhat run scripts/balance.cts --network sepolia
 *
 * Environment:
 *   DEPLOYER_PRIVATE_KEY - For deployer account (optional)
 *   PRIVATE_KEY - For operations account (optional)
 *   ADDRESSES - Comma-separated list of additional addresses or private keys (optional)
 */

import hre from "hardhat";
import "dotenv/config";
import { getBalance } from "@midl/core";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getNetworkInfo } = require("../lib/deploy.cts");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const {
  getMidlEnvironment,
  midlDeriveEvmAddress,
  midlDeriveBtcAddress,
  midlGetOperationsAddresses,
  hasMidlPlugin,
} = require("../lib/midl.cts");

// Type import for MidlEnvironment
import type { MidlEnvironment } from "../lib/midl.cts";

// =============================================================================
// Types
// =============================================================================

type AddressType = "private_key" | "evm_address" | "btc_address";

interface AccountInfo {
  label: string;
  evmAddress?: string;
  btcAddress?: string;
  evmBalance?: string;
  btcBalance?: string;
  nonce?: number;
  error?: string;
}

// =============================================================================
// Address Detection
// =============================================================================

/**
 * Detect the type of input (private key, EVM address, or BTC address)
 */
function detectAddressType(input: string): AddressType | null {
  // Remove whitespace
  input = input.trim();

  // Private key: 0x + 64 hex chars or just 64 hex chars
  if (input.startsWith("0x") && input.length === 66) {
    if (/^0x[0-9a-fA-F]{64}$/.test(input)) {
      return "private_key";
    }
  } else if (input.length === 64 && /^[0-9a-fA-F]{64}$/.test(input)) {
    return "private_key";
  }

  // EVM address: 0x + 40 hex chars
  if (input.startsWith("0x") && input.length === 42) {
    if (/^0x[0-9a-fA-F]{40}$/.test(input)) {
      return "evm_address";
    }
  }

  // BTC address: bcrt1... (regtest), bc1... (mainnet), tb1... (testnet)
  if (
    input.startsWith("bcrt1") ||
    input.startsWith("bc1") ||
    input.startsWith("tb1")
  ) {
    return "btc_address";
  }

  return null;
}

/**
 * Parse additional addresses from ADDRESSES environment variable
 */
function parseAddresses(): string[] {
  const addresses = process.env.ADDRESSES;
  if (!addresses) {
    return [];
  }
  return addresses
    .split(",")
    .map((addr) => addr.trim())
    .filter((addr) => addr.length > 0);
}

// =============================================================================
// EVM Balance Fetcher
// =============================================================================

async function getEvmAccountInfo(
  address: string,
  label: string
): Promise<AccountInfo> {
  try {
    const [balance, nonce] = await Promise.all([
      hre.ethers.provider.getBalance(address),
      hre.ethers.provider.getTransactionCount(address),
    ]);

    return {
      label,
      evmAddress: address,
      evmBalance: hre.ethers.formatEther(balance),
      nonce,
    };
  } catch (error) {
    return {
      label,
      evmAddress: address,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

// =============================================================================
// MIDL Balance Fetcher
// =============================================================================

let midlEnvironmentCache: MidlEnvironment | null = null;

async function getMidlEnv(): Promise<MidlEnvironment | null> {
  if (midlEnvironmentCache) {
    return midlEnvironmentCache;
  }

  if (!hasMidlPlugin(hre)) {
    return null;
  }

  try {
    const midl: MidlEnvironment = getMidlEnvironment(hre);
    await midl.initialize(0); // Initialize with operations wallet
    midlEnvironmentCache = midl;
    return midl;
  } catch {
    return null;
  }
}

async function getMidlAccountInfo(
  evmAddress: string,
  btcAddress: string,
  label: string,
  _privateKey?: string
): Promise<AccountInfo> {
  try {
    // Get EVM balance and nonce
    const [evmBalance, nonce] = await Promise.all([
      hre.ethers.provider.getBalance(evmAddress),
      hre.ethers.provider.getTransactionCount(evmAddress),
    ]);

    // Get BTC balance using the MIDL API
    let btcBalanceSats = 0;
    try {
      const midl = await getMidlEnv();
      if (midl) {
        const config = midl.getConfig();
        if (config) {
          btcBalanceSats = await getBalance(config, btcAddress);
        }
      }
    } catch {
      // If we can't connect to MIDL, still show EVM balance
    }

    const btcBalance = (btcBalanceSats / 100_000_000).toFixed(8);

    return {
      label,
      evmAddress,
      btcAddress,
      evmBalance: hre.ethers.formatEther(evmBalance),
      btcBalance: `${btcBalance} (${btcBalanceSats} sats)`,
      nonce,
    };
  } catch (error) {
    return {
      label,
      evmAddress,
      btcAddress,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function getMidlBtcOnlyInfo(
  btcAddress: string,
  label: string
): Promise<AccountInfo> {
  try {
    // For BTC-only addresses, we need hre.midl initialized to query balance
    const midl = await getMidlEnv();
    if (!midl) {
      return {
        label,
        btcAddress,
        btcBalance: "(MIDL plugin required to query)",
      };
    }

    const config = midl.getConfig();
    if (!config) {
      return {
        label,
        btcAddress,
        btcBalance: "(MIDL config not initialized)",
      };
    }

    const btcBalanceSats = await getBalance(config, btcAddress);
    const btcBalance = (btcBalanceSats / 100_000_000).toFixed(8);

    return {
      label,
      btcAddress,
      btcBalance: `${btcBalance} (${btcBalanceSats} sats)`,
    };
  } catch (error) {
    return {
      label,
      btcAddress,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

// =============================================================================
// Table Formatting
// =============================================================================

function padRight(str: string, len: number): string {
  return str.length >= len ? str : str + " ".repeat(len - str.length);
}

function padLeft(str: string, len: number): string {
  return str.length >= len ? str : " ".repeat(len - str.length) + str;
}

function printEvmTable(accounts: AccountInfo[]): void {
  // Calculate column widths
  const labelWidth = Math.max(10, ...accounts.map((a) => a.label.length));
  const addressWidth = 42; // EVM addresses are 42 chars
  const nonceWidth = 7;
  const balanceWidth = Math.max(
    14,
    ...accounts.map((a) => (a.evmBalance ? a.evmBalance.length + 4 : 10))
  );

  // Print header
  const divider =
    "+" +
    "-".repeat(labelWidth + 2) +
    "+" +
    "-".repeat(addressWidth + 2) +
    "+" +
    "-".repeat(nonceWidth + 2) +
    "+" +
    "-".repeat(balanceWidth + 2) +
    "+";

  console.log(divider);
  console.log(
    "| " +
      padRight("Account", labelWidth) +
      " | " +
      padRight("Address", addressWidth) +
      " | " +
      padRight("Nonce", nonceWidth) +
      " | " +
      padRight("Balance", balanceWidth) +
      " |"
  );
  console.log(divider);

  // Print rows
  for (const account of accounts) {
    if (account.error) {
      console.log(
        "| " +
          padRight(account.label, labelWidth) +
          " | " +
          padRight(account.evmAddress || "N/A", addressWidth) +
          " | " +
          padRight("ERR", nonceWidth) +
          " | " +
          padRight(account.error.slice(0, balanceWidth), balanceWidth) +
          " |"
      );
    } else {
      console.log(
        "| " +
          padRight(account.label, labelWidth) +
          " | " +
          padRight(account.evmAddress || "N/A", addressWidth) +
          " | " +
          padLeft(String(account.nonce ?? "N/A"), nonceWidth) +
          " | " +
          padRight(
            (account.evmBalance || "0") + " ETH",
            balanceWidth
          ) +
          " |"
      );
    }
  }

  console.log(divider);
}

function printMidlTable(accounts: AccountInfo[]): void {
  // Calculate column widths
  const labelWidth = Math.max(10, ...accounts.map((a) => a.label.length));
  const addressWidth = 44; // BTC regtest addresses can be longer
  const nonceWidth = 7;
  const evmBalanceWidth = 16;
  const btcBalanceWidth = Math.max(
    20,
    ...accounts.map((a) => (a.btcBalance ? a.btcBalance.length : 10))
  );

  // Print header
  const divider =
    "+" +
    "-".repeat(labelWidth + 2) +
    "+" +
    "-".repeat(addressWidth + 2) +
    "+" +
    "-".repeat(nonceWidth + 2) +
    "+" +
    "-".repeat(evmBalanceWidth + 2) +
    "+" +
    "-".repeat(btcBalanceWidth + 2) +
    "+";

  console.log(divider);
  console.log(
    "| " +
      padRight("Account", labelWidth) +
      " | " +
      padRight("Address", addressWidth) +
      " | " +
      padRight("Nonce", nonceWidth) +
      " | " +
      padRight("EVM Balance", evmBalanceWidth) +
      " | " +
      padRight("BTC Balance", btcBalanceWidth) +
      " |"
  );
  console.log(divider);

  // Print rows (each account gets 2 rows for EVM and BTC addresses)
  for (const account of accounts) {
    if (account.error) {
      console.log(
        "| " +
          padRight(account.label, labelWidth) +
          " | " +
          padRight(account.evmAddress || account.btcAddress || "N/A", addressWidth) +
          " | " +
          padRight("ERR", nonceWidth) +
          " | " +
          padRight("", evmBalanceWidth) +
          " | " +
          padRight(account.error.slice(0, btcBalanceWidth), btcBalanceWidth) +
          " |"
      );
    } else if (account.evmAddress && account.btcAddress) {
      // Full account with both addresses - show EVM row
      console.log(
        "| " +
          padRight(account.label, labelWidth) +
          " | " +
          padRight("EVM: " + account.evmAddress.slice(0, addressWidth - 5), addressWidth) +
          " | " +
          padLeft(String(account.nonce ?? "N/A"), nonceWidth) +
          " | " +
          padRight((account.evmBalance || "0") + " ETH", evmBalanceWidth) +
          " | " +
          padRight(account.btcBalance || "0", btcBalanceWidth) +
          " |"
      );
      // BTC row
      console.log(
        "| " +
          padRight("", labelWidth) +
          " | " +
          padRight("BTC: " + account.btcAddress.slice(0, addressWidth - 5), addressWidth) +
          " | " +
          padRight("", nonceWidth) +
          " | " +
          padRight("", evmBalanceWidth) +
          " | " +
          padRight("", btcBalanceWidth) +
          " |"
      );
    } else if (account.btcAddress) {
      // BTC-only address
      console.log(
        "| " +
          padRight(account.label, labelWidth) +
          " | " +
          padRight("BTC: " + account.btcAddress.slice(0, addressWidth - 5), addressWidth) +
          " | " +
          padRight("N/A", nonceWidth) +
          " | " +
          padRight("N/A", evmBalanceWidth) +
          " | " +
          padRight(account.btcBalance || "0", btcBalanceWidth) +
          " |"
      );
    } else if (account.evmAddress) {
      // EVM-only address
      console.log(
        "| " +
          padRight(account.label, labelWidth) +
          " | " +
          padRight("EVM: " + account.evmAddress.slice(0, addressWidth - 5), addressWidth) +
          " | " +
          padLeft(String(account.nonce ?? "N/A"), nonceWidth) +
          " | " +
          padRight((account.evmBalance || "0") + " ETH", evmBalanceWidth) +
          " | " +
          padRight("N/A", btcBalanceWidth) +
          " |"
      );
    }
  }

  console.log(divider);
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  const networkInfo = await getNetworkInfo(hre);

  console.log("\nBalance Checker");
  console.log("===============");
  console.log(`Network: ${networkInfo.name} (chainId: ${networkInfo.chainId})`);

  const accounts: AccountInfo[] = [];
  const customAddresses = parseAddresses();

  if (networkInfo.isMidl) {
    await fetchMidlBalances(accounts, customAddresses);
    console.log("");
    printMidlTable(accounts);
  } else {
    await fetchEvmBalances(accounts, customAddresses);
    console.log("");
    printEvmTable(accounts);
  }
}

async function fetchEvmBalances(
  accounts: AccountInfo[],
  customAddresses: string[]
): Promise<void> {
  // Deployer account
  if (process.env.DEPLOYER_PRIVATE_KEY) {
    const deployer = new hre.ethers.Wallet(process.env.DEPLOYER_PRIVATE_KEY);
    const deployerAddress = await deployer.getAddress();
    accounts.push(await getEvmAccountInfo(deployerAddress, "Deployer"));
  }

  // Operations account
  if (process.env.PRIVATE_KEY) {
    const operations = new hre.ethers.Wallet(process.env.PRIVATE_KEY);
    const operationsAddress = await operations.getAddress();
    accounts.push(await getEvmAccountInfo(operationsAddress, "Operations"));
  }

  // Custom addresses from ADDRESSES env var
  for (let i = 0; i < customAddresses.length; i++) {
    const addr = customAddresses[i];
    const type = detectAddressType(addr);
    const label = `Custom ${i + 1}`;

    if (type === "private_key") {
      const wallet = new hre.ethers.Wallet(addr);
      const address = await wallet.getAddress();
      accounts.push(await getEvmAccountInfo(address, label));
    } else if (type === "evm_address") {
      accounts.push(await getEvmAccountInfo(addr, label));
    } else {
      accounts.push({
        label,
        error: `Invalid address format: ${addr.slice(0, 20)}...`,
      });
    }
  }

  if (accounts.length === 0) {
    console.log(
      "\nNo accounts to display. Set DEPLOYER_PRIVATE_KEY or PRIVATE_KEY in .env, or set ADDRESSES env var."
    );
  }
}

async function fetchMidlBalances(
  accounts: AccountInfo[],
  customAddresses: string[]
): Promise<void> {
  // Deployer account
  if (process.env.DEPLOYER_PRIVATE_KEY) {
    const evmAddress = midlDeriveEvmAddress(process.env.DEPLOYER_PRIVATE_KEY);
    const btcAddress = midlDeriveBtcAddress(
      process.env.DEPLOYER_PRIVATE_KEY,
      "regtest"
    );
    accounts.push(
      await getMidlAccountInfo(
        evmAddress,
        btcAddress,
        "Deployer",
        process.env.DEPLOYER_PRIVATE_KEY
      )
    );
  }

  // Operations account
  if (process.env.PRIVATE_KEY) {
    const addresses = midlGetOperationsAddresses("regtest");
    if (addresses) {
      accounts.push(
        await getMidlAccountInfo(
          addresses.evm,
          addresses.btc,
          "Operations",
          process.env.PRIVATE_KEY
        )
      );
    }
  }

  // Custom addresses from ADDRESSES env var
  for (let i = 0; i < customAddresses.length; i++) {
    const addr = customAddresses[i];
    const type = detectAddressType(addr);
    const label = `Custom ${i + 1}`;

    if (type === "private_key") {
      const evmAddress = midlDeriveEvmAddress(addr);
      const btcAddress = midlDeriveBtcAddress(addr, "regtest");
      accounts.push(
        await getMidlAccountInfo(evmAddress, btcAddress, label, addr)
      );
    } else if (type === "evm_address") {
      // EVM-only address on MIDL
      const info = await getEvmAccountInfo(addr, label);
      accounts.push({
        ...info,
        btcAddress: undefined,
        btcBalance: "N/A (EVM only)",
      });
    } else if (type === "btc_address") {
      // BTC-only address
      accounts.push(await getMidlBtcOnlyInfo(addr, label));
    } else {
      accounts.push({
        label,
        error: `Invalid address format: ${addr.slice(0, 20)}...`,
      });
    }
  }

  if (accounts.length === 0) {
    console.log(
      "\nNo accounts to display. Set DEPLOYER_PRIVATE_KEY or PRIVATE_KEY in .env, or set ADDRESSES env var."
    );
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

export { main as balance };
