// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import fs from "fs";
import path from "path";
import { getBalance } from "@midl/core";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { loadReleaseBytecode } = require("../../lib/deploy.cts");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getMidlEnvironment } = require("../../lib/midl.cts");

// Type import for MidlEnvironment
import type { MidlEnvironment } from "../../lib/midl.cts";

/**
 * MIDL QuipPaymaster Deployment
 *
 * Mirrors `script/DeployPaymaster.s.sol`: deploys both the QuipPaymaster
 * implementation and the canonical ERC1967 proxy through the Deployer.
 *
 * Two CREATE3 deploys:
 *   1. Implementation — bytecode from the Foundry-built release snapshot
 *      (`deployments/bytecode/QuipPaymaster.sol/latest.json`), salt
 *      keccak256("QUIP:QuipPaymaster:Impl:V1"). Constructor is empty + calls
 *      _disableInitializers(), so the impl is inert.
 *   2. ERC1967 proxy — creation code composed at deploy time from
 *      `out/ERC1967Proxy.sol/ERC1967Proxy.json` + abi.encode(impl, initData)
 *      where initData = initialize(PAYMASTER_OWNER). Salt
 *      keccak256("QUIP:QuipPaymaster:Proxy:V1"). The proxy is intentionally
 *      not snapshotted in the release: its bytecode embeds the per-chain
 *      owner, so it must be composed here.
 *
 * Prerequisites:
 * - Deployer contract must be deployed (--tags Deployer first)
 * - WOTSPlus library must be deployed (--tags WOTSPlus first; impl links it)
 * - Operations wallet must have funds
 * - PAYMASTER_OWNER env var must be set
 *
 * Usage:
 *   PAYMASTER_OWNER=0x... npx hardhat deploy --network midl_regtest --tags QuipPaymaster
 */

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  console.log("MIDL QuipPaymaster Deployment");
  console.log("==============================");

  // Validate PAYMASTER_OWNER is set
  const paymasterOwner = process.env.PAYMASTER_OWNER;
  if (!paymasterOwner) {
    throw new Error("PAYMASTER_OWNER must be set in env / .env file");
  }
  if (!hre.ethers.isAddress(paymasterOwner)) {
    throw new Error(`PAYMASTER_OWNER is not a valid address: ${paymasterOwner}`);
  }
  if (paymasterOwner === hre.ethers.ZeroAddress) {
    throw new Error("PAYMASTER_OWNER must be non-zero");
  }

  // Get MIDL environment (uses private key if available, falls back to mnemonic)
  const midl: MidlEnvironment = getMidlEnvironment(hre, "midl_regtest");

  console.log("Initializing MIDL connection...");
  await midl.initialize(0);

  const account = midl.getAccount();
  const btcAddress = account.address;
  const addressType = account.addressType || "unknown";
  const evmAddress = midl.getEVMAddress();
  console.log(`\nOperations Wallet:`);
  console.log(`  Bitcoin: ${btcAddress} (${addressType})`);
  console.log(`  EVM:     ${evmAddress}`);
  console.log(`\nPaymaster owner: ${paymasterOwner}`);

  // Check for Deployer contract
  const deployerDeployment = await midl.getDeployment("Deployer");
  if (!deployerDeployment) {
    throw new Error(
      "Deployer contract not found.\n" +
        "Run deployment with --tags Deployer first using midl_regtest_deployer network."
    );
  }
  console.log(`\nDeployer contract: ${deployerDeployment.address}`);

  // ── Implementation address: from release snapshot ──────────────────────
  const implRelease = loadReleaseBytecode("QuipPaymaster.sol");
  const implExpectedAddress = implRelease.address;

  // ── Proxy address: compute via CREATE3 from this chain's Deployer ──────
  // Salts mirror script/Deploy*.s.sol exactly:
  //   keccak256("QUIP:QuipPaymaster:Proxy:V1").
  const proxySalt = hre.ethers.id("QUIP:QuipPaymaster:Proxy:V1");
  const proxyExpectedAddress = computeCreate3Address(
    hre,
    deployerDeployment.address,
    proxySalt
  );

  console.log(`Expected impl:  ${implExpectedAddress}`);
  console.log(`Expected proxy: ${proxyExpectedAddress}`);

  // Get signer and connect to Deployer contract
  const [signer] = await hre.ethers.getSigners();
  const deployer = await hre.ethers.getContractAt(
    "Deployer",
    deployerDeployment.address,
    signer
  );

  // Query BTC balance from MIDL (single check covers both deploys)
  const config = midl.getConfig();
  if (!config) throw new Error("MIDL config not initialized");
  const btcBalanceSats = await getBalance(config, btcAddress);
  const btcBalance = btcBalanceSats / 100_000_000;
  console.log(`\nBTC Balance: ${btcBalance} BTC (${btcBalanceSats} sats)`);

  // ── Step 1: Deploy implementation ──────────────────────────────────────
  let implAddress: string;
  const existingImplCode = await hre.ethers.provider.getCode(implExpectedAddress);
  if (existingImplCode !== "0x") {
    console.log(`\nImplementation already deployed at: ${implExpectedAddress}`);
    console.log("Skipping impl deployment.");
    implAddress = implExpectedAddress;
  } else {
    if (btcBalanceSats === 0) {
      throw new Error(
        `Operations wallet has no BTC balance.\n` +
          `Fund ${btcAddress} with testnet BTC from: https://faucet.regtest.midl.xyz`
      );
    }

    console.log("\n--- Deploying QuipPaymaster implementation ---");
    console.log(`Bytecode size: ${(implRelease.creationBytecode.length - 2) / 2} bytes`);

    const tx = await deployer.deploy(implRelease.creationBytecode, implRelease.salt);
    console.log(`Transaction submitted: ${tx.hash}`);
    console.log("Waiting for confirmation...");

    const receipt = await tx.wait();
    if (!receipt) {
      throw new Error("Impl transaction failed - no receipt");
    }

    implAddress = parseDeployedAddress(deployer, receipt);
    if (implAddress !== implExpectedAddress) {
      console.warn(
        `WARNING: Deployed impl ${implAddress} doesn't match expected ${implExpectedAddress}`
      );
    }
    console.log(`Implementation deployed at: ${implAddress}`);
  }

  // ── Step 2: Deploy + initialize ERC1967 proxy ──────────────────────────
  // The proxy's `constructor(address impl, bytes data)` runs
  // `upgradeToAndCall(impl, data)` which delegatecalls `data` against `impl`.
  // With `data = initialize(PAYMASTER_OWNER)`, the proxy is fully initialized
  // atomically with the CREATE3 deploy.
  let proxyAddress: string;
  const existingProxyCode = await hre.ethers.provider.getCode(proxyExpectedAddress);
  if (existingProxyCode !== "0x") {
    console.log(`\nProxy already deployed at: ${proxyExpectedAddress}`);
    console.log("Verifying owner.");
    proxyAddress = proxyExpectedAddress;
    await assertProxyOwner(hre, proxyAddress, paymasterOwner);
  } else {
    if (btcBalanceSats === 0) {
      throw new Error(
        `Operations wallet has no BTC balance.\n` +
          `Fund ${btcAddress} with testnet BTC from: https://faucet.regtest.midl.xyz`
      );
    }

    console.log("\n--- Deploying QuipPaymaster proxy ---");

    // Read ERC1967Proxy creation bytecode from Foundry's out/.
    const proxyArtifactPath = path.join(
      __dirname,
      "../../out/ERC1967Proxy.sol/ERC1967Proxy.json"
    );
    if (!fs.existsSync(proxyArtifactPath)) {
      throw new Error(
        `ERC1967Proxy Foundry artifact not found: ${proxyArtifactPath}\nRun \`forge build\` first.`
      );
    }
    const proxyArtifact = JSON.parse(fs.readFileSync(proxyArtifactPath, "utf-8"));
    const proxyCreationCode: string = proxyArtifact.bytecode.object;

    // Encode initData = initialize(PAYMASTER_OWNER) using the QuipPaymaster
    // ABI from the same Foundry build that produced the impl bytecode.
    const paymasterArtifactPath = path.join(
      __dirname,
      "../../out/QuipPaymaster.sol/QuipPaymaster.json"
    );
    const paymasterArtifact = JSON.parse(
      fs.readFileSync(paymasterArtifactPath, "utf-8")
    );
    const paymasterIface = new hre.ethers.Interface(paymasterArtifact.abi);
    const initData = paymasterIface.encodeFunctionData("initialize", [
      paymasterOwner,
    ]);

    // Compose proxy creation code: ERC1967Proxy bytecode + abi.encode(impl, data)
    const encodedCtorArgs = hre.ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "bytes"],
      [implAddress, initData]
    );
    const proxyBytecode = proxyCreationCode + encodedCtorArgs.slice(2);
    console.log(`Proxy bytecode size: ${(proxyBytecode.length - 2) / 2} bytes`);

    const tx = await deployer.deploy(proxyBytecode, proxySalt);
    console.log(`Transaction submitted: ${tx.hash}`);
    console.log("Waiting for confirmation...");

    const receipt = await tx.wait();
    if (!receipt) {
      throw new Error("Proxy transaction failed - no receipt");
    }

    proxyAddress = parseDeployedAddress(deployer, receipt);
    if (proxyAddress !== proxyExpectedAddress) {
      console.warn(
        `WARNING: Deployed proxy ${proxyAddress} doesn't match expected ${proxyExpectedAddress}`
      );
    }
    console.log(`Proxy deployed at: ${proxyAddress}`);
    await assertProxyOwner(hre, proxyAddress, paymasterOwner);
  }

  console.log("\n==============================");
  console.log("QuipPaymaster Deployment Complete!");
  console.log("==============================");
  console.log(`Implementation:    ${implAddress}`);
  console.log(`Proxy (canonical): ${proxyAddress}`);
  console.log(`Owner:             ${paymasterOwner}`);
};

// ── Helpers ────────────────────────────────────────────────────────────

/**
 * Parse the Deploy event from a Deployer receipt to get the deployed address.
 */
function parseDeployedAddress(
  deployer: { interface: { getEvent: (name: string) => { topicHash: string } | null; parseLog: (log: { topics: ReadonlyArray<string>; data: string }) => { args: { addr: string } } | null } },
  receipt: { logs: ReadonlyArray<{ topics: ReadonlyArray<string>; data: string }> }
): string {
  const deployEventTopic = deployer.interface.getEvent("Deploy")?.topicHash;
  const deployEvent = receipt.logs.find(
    (log) => log.topics[0] === deployEventTopic
  );
  if (!deployEvent) {
    throw new Error("Deploy event not found in transaction receipt");
  }
  const parsed = deployer.interface.parseLog({
    topics: deployEvent.topics,
    data: deployEvent.data,
  });
  if (!parsed) {
    throw new Error("Failed to parse Deploy event log");
  }
  return parsed.args.addr;
}

/**
 * Predict the CREATE3 address of a contract deployed via the Deployer.
 * Mirrors Solady's CREATE3.predictDeterministicAddress(salt, deployer).
 */
function computeCreate3Address(
  hre: HardhatRuntimeEnvironment,
  deployerAddress: string,
  salt: string
): string {
  // Solady CREATE3 proxy initcode hash:
  //   keccak256(hex"67363d3d37363d34f03d5260086018f3")
  const PROXY_INITCODE_HASH =
    "0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f";

  const proxyAddress = hre.ethers.getCreate2Address(
    deployerAddress,
    salt,
    PROXY_INITCODE_HASH
  );
  return hre.ethers.getCreateAddress({ from: proxyAddress, nonce: 1 });
}

/**
 * Read `owner()` off the proxy and revert if it doesn't match the expected
 * owner. Catches the (otherwise silent) failure mode where deploy + init land
 * the proxy at the predicted address but initialize() did not run as expected.
 */
async function assertProxyOwner(
  hre: HardhatRuntimeEnvironment,
  proxyAddress: string,
  expected: string
): Promise<void> {
  const paymasterArtifactPath = path.join(
    __dirname,
    "../../out/QuipPaymaster.sol/QuipPaymaster.json"
  );
  const paymasterArtifact = JSON.parse(
    fs.readFileSync(paymasterArtifactPath, "utf-8")
  );
  const proxy = new hre.ethers.Contract(
    proxyAddress,
    paymasterArtifact.abi,
    hre.ethers.provider
  );
  const actual: string = await proxy.owner();
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(
      `Paymaster owner mismatch on proxy ${proxyAddress}:\n` +
        `  expected: ${expected}\n` +
        `  actual:   ${actual}`
    );
  }
  console.log(`Verified proxy.owner() == ${actual}`);
}

export default func;
func.tags = ["QuipPaymaster"];
func.dependencies = ["WOTSPlus"];
// Only run on MIDL networks
func.skip = async (hre: HardhatRuntimeEnvironment) => {
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  return chainId !== 777; // MIDL chain ID
};
