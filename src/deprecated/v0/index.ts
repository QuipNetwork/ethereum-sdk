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
 * @deprecated LEGACY — v0 contract surface only.
 *
 * This module targets the original (pre-v1) QuipWallet/QuipFactory deployments:
 * the single-`pqOwner` model, the two-key recovery payload, and the v0 upgrade
 * payload layout. It is kept solely so existing v0 wallets remain operable.
 *
 * Do NOT use it against v1 wallets — the method names, payload shapes, and
 * codec offsets do not match the v1 contract ABI and will produce malformed
 * payloads or calls to functions that no longer exist.
 *
 * For all new integrations import from `@quip.network/ethereum-sdk/v1` instead.
 */
import { ethers } from "ethers";
import { QuipWallet__factory } from "./typechain-types/factories/contracts/QuipWallet__factory.js";
import { QuipFactory__factory } from "./typechain-types/factories/contracts/QuipFactory__factory.js";
import type { QuipFactory } from "./typechain-types/contracts/QuipFactory.js";
import type { QuipWallet } from "./typechain-types/contracts/QuipWallet.js";
import {
  computeVaultAddress,
  getNetworkAddresses,
  CHAIN_IDS,
} from "./addresses.js";

import { WOTSPlus } from "@quip.network/hashsigs";
import { keccak_256 } from "@noble/hashes/sha3";
import { randomBytes } from "@noble/ciphers/webcrypto";

// Add explicit exports for contract interfaces and events
// For whatever reason, typechain-types/index.ts does not do these
// exports for us.
export * from "./typechain-types/contracts/Deployer.js";
export {
  QuipFactory,
  QuipCreatedEvent,
} from "./typechain-types/contracts/QuipFactory.js";
export {
  QuipWallet,
  pqTransferEvent,
} from "./typechain-types/contracts/QuipWallet.js";

// Export factories
export { QuipWallet__factory } from "./typechain-types/factories/contracts/QuipWallet__factory.js";
export { QuipFactory__factory } from "./typechain-types/factories/contracts/QuipFactory__factory.js";

export * from "./addresses.js";
export * from "./constants.js";

export const SUPPORTED_NETWORKS = {
  SEPOLIA: "sepolia",
  SEPOLIA_OPTIMISM: "sepolia_optimism",
  SEPOLIA_BASE: "sepolia_base",
  MAINNET: "mainnet",
  BASE: "base",
  OPTIMISM: "optimism",
  MIDL_TESTNET: "midl",
} as const;

export type NetworkType =
  (typeof SUPPORTED_NETWORKS)[keyof typeof SUPPORTED_NETWORKS];

export interface WinternitzKeyPair {
  privateKey: Uint8Array;
  publicKey: WinternitzPublicKey;
}

export interface WinternitzPublicKey {
  publicSeed: Uint8Array;
  publicKeyHash: Uint8Array;
}

export class QuipSigner {
  // FIXME: in an ideal world these are kept in a secure wallet somewhere and this is
  // merely an interface. For now we are keeping them in memory.
  private quantumSecret: Uint8Array;
  private wots: WOTSPlus;

  constructor(quantumSecret: Uint8Array) {
    this.wots = new WOTSPlus(keccak_256);
    this.quantumSecret = keccak_256(quantumSecret);
  }

  // generateKeyPair in the domain of a specific vault using the base quantum
  // secret.
  public generateKeyPair(vaultId: Uint8Array): WinternitzKeyPair {
    const publicSeed = randomBytes(32);
    return this.recoverKeyPair(vaultId, publicSeed);
  }

  // recoverKeyPair given a pre-existing public seed, and vault id
  public recoverKeyPair(
    vaultId: Uint8Array,
    publicSeed: Uint8Array
  ): WinternitzKeyPair {
    const privateSeed = Uint8Array.from([...this.quantumSecret, ...vaultId]);
    const keypair = this.wots.generateKeyPair(privateSeed, publicSeed);
    const returnedSeed = keypair.publicKey.slice(0, 32);
    if (!Buffer.from(publicSeed).equals(Buffer.from(returnedSeed))) {
      throw new Error("Invalid public seed returned: " + returnedSeed);
    }
    return {
      privateKey: keypair.privateKey,
      publicKey: {
        publicSeed: keypair.publicKey.slice(0, 32),
        publicKeyHash: keypair.publicKey.slice(32, 64),
      },
    };
  }

  public sign(
    message: Uint8Array,
    vaultId: Uint8Array,
    publicSeed: Uint8Array
  ): Uint8Array[] {
    const key = this.recoverKeyPair(vaultId, publicSeed);
    return this.wots.sign(key.privateKey, key.publicKey.publicSeed, message);
  }
}

export class QuipWalletClient {
  private wallet: QuipWallet;
  private quipSigner: QuipSigner;
  private vaultId: Uint8Array;

  constructor(quipSigner: QuipSigner, vaultId: Uint8Array, wallet: QuipWallet) {
    this.wallet = wallet;
    this.vaultId = vaultId;
    this.quipSigner = quipSigner;
  }

  async getPqOwner() {
    return await this.wallet.pqOwner();
  }

  async getAddress() {
    return this.wallet.getAddress();
  }

  async getTransferFee(): Promise<bigint> {
    return await this.wallet.getTransferFee();
  }

  async getExecuteFee(): Promise<bigint> {
    return await this.wallet.getExecuteFee();
  }

  async transferWithWinternitz(
    to: ethers.AddressLike,
    value: bigint,
    options: { gasLimit?: bigint } = {}
  ) {
    const nextPqOwner = this.quipSigner.generateKeyPair(this.vaultId);
    const currentPqOwner = await this.wallet.pqOwner();
    const publicSeed = ethers.getBytes(currentPqOwner.publicSeed);
    const transferFee = await this.getTransferFee();

    // TODO: Make a function that does this?
    const packedMessageData = ethers.solidityPacked(
      ["bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256"],
      [
        currentPqOwner.publicSeed,
        currentPqOwner.publicKeyHash,
        nextPqOwner.publicKey.publicSeed,
        nextPqOwner.publicKey.publicKeyHash,
        to,
        value,
      ]
    );

    // FIXME: these are stupid in hindsight.
    const message = {
      messageHash: keccak_256(ethers.getBytes(packedMessageData)),
    };
    const pqSig = {
      elements: this.quipSigner.sign(
        message.messageHash,
        this.vaultId,
        publicSeed
      ),
    };

    let gasLimit: bigint;
    if (options.gasLimit) {
      gasLimit = options.gasLimit;
    }

    // Use provided gas limit or the estimated one (or none if estimation failed)
    const txopts = {
      value: transferFee,
      ...(gasLimit! && { gasLimit }),
    };

    const tx = await this.wallet.transferWithWinternitz(
      nextPqOwner.publicKey,
      pqSig,
      to,
      value,
      txopts
    );
    return await tx.wait();
  }

  async executeWithWinternitz(
    target: ethers.AddressLike,
    opdata: Uint8Array,
    options: {
      gasLimit?: bigint;
      value?: bigint;
    } = {}
  ) {
    const nextPqOwner = this.quipSigner.generateKeyPair(this.vaultId);
    const currentPqOwner = await this.wallet.pqOwner();
    const publicSeed = ethers.getBytes(currentPqOwner.publicSeed);
    const executeFee = await this.getExecuteFee() + (options.value ?? 0n);

    const packedMessageData = ethers.solidityPacked(
      ["bytes32", "bytes32", "bytes32", "bytes32", "address", "bytes"],
      [
        currentPqOwner.publicSeed,
        currentPqOwner.publicKeyHash,
        nextPqOwner.publicKey.publicSeed,
        nextPqOwner.publicKey.publicKeyHash,
        target,
        opdata,
      ]
    );

    const message = {
      messageHash: keccak_256(ethers.getBytes(packedMessageData)),
    };
    const pqSig = {
      elements: this.quipSigner.sign(
        message.messageHash,
        this.vaultId,
        publicSeed
      ),
    };

    let gasLimit: bigint;
    try {
      // Try to estimate gas
      const estimatedGas = await this.wallet.executeWithWinternitz.estimateGas(
        nextPqOwner.publicKey,
        pqSig,
        target,
        opdata,
        { value: executeFee }
      );
      gasLimit = (estimatedGas * 120n) / 100n; // 20% buffer
    } catch (error: any) {
      // Log detailed error information
      console.error("Gas estimation failed:");
      console.error("Target:", target);
      console.error("Operation data length:", opdata.length);
      console.error("Execute fee:", executeFee.toString());

      if (error.transaction) {
        // Log the transaction that would have been sent
        console.error("Failed transaction:", {
          to: error.transaction.to,
          from: error.transaction.from,
          data: error.transaction.data?.slice(0, 66) + "...", // First 32 bytes + '...'
        });
      }

      // If there's a specific revert reason, it might be in error.reason
      if (error.reason) {
        console.error("Revert reason:", error.reason);
      }

      // Print error with more context, but we don't throw here because
      // some wallets like Safe can't estimate gas properly.
      console.error(`Gas estimation failed: ${error.message || error}`);
    }

    if (options.gasLimit) {
      gasLimit = options.gasLimit;
    }

    // Use provided gas limit or the estimated one (or none if estimation failed)
    const txopts = {
      value: executeFee,
      ...(gasLimit! && { gasLimit }),
    };

    const tx = await this.wallet.executeWithWinternitz(
      nextPqOwner.publicKey,
      pqSig,
      target,
      opdata,
      txopts
    );
    return await tx.wait();
  }
}

/**
 * EIP-1193 compatible wallet provider interface
 * Both ethers.js and MIDL.js providers implement this interface
 */
export interface WalletProvider {
  request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
}

export class QuipClient {
  private provider: ethers.Provider;
  private signer?: ethers.Signer;
  private factory?: QuipFactory;
  private initializationPromise: Promise<void>;
  private chainId?: number;

  /**
   * Create a QuipClient instance
   * Works with any EIP-1193 compatible provider (ethers.js, MIDL.js, etc.)
   *
   * @param provider - An EIP-1193 compatible wallet provider
   */
  constructor(provider: ethers.Eip1193Provider | WalletProvider) {
    this.provider = new ethers.BrowserProvider(provider as ethers.Eip1193Provider);
    this.initializationPromise = this.initialize();
  }

  /**
   * Factory method for creating QuipClient instances
   * Provides a cleaner async initialization pattern
   */
  static async create(provider: ethers.Eip1193Provider | WalletProvider): Promise<QuipClient> {
    const client = new QuipClient(provider);
    await client.initializationPromise;
    return client;
  }

  private async initialize() {
    await this.setSigner();
    await this.detectNetwork();
    await this.setQuipFactory();
  }

  private async setSigner() {
    if (this.provider instanceof ethers.BrowserProvider) {
      this.signer = await this.provider.getSigner();
    }
  }

  private async detectNetwork() {
    const network = await this.provider.getNetwork();
    this.chainId = Number(network.chainId);
  }

  private async setQuipFactory() {
    // Get network-appropriate factory address
    const addresses = getNetworkAddresses(this.chainId);
    this.factory = QuipFactory__factory.connect(
      addresses.QuipFactory,
      this.signer!
    );
  }

  /**
   * Get the current chain ID
   * @returns The chain ID of the connected network
   */
  getChainId(): number {
    if (!this.chainId) {
      throw new Error("Client not initialized. Call await client.initializationPromise first.");
    }
    return this.chainId;
  }

  /**
   * Check if connected to MIDL network
   * @returns true if connected to MIDL testnet (chain ID 777)
   */
  isMidlNetwork(): boolean {
    return this.chainId === CHAIN_IDS.MIDL_TESTNET;
  }

  /**
   * Get the connected wallet's owner address
   * Returns EVM-format address regardless of underlying wallet type
   * (MIDL.js derives EVM address from Bitcoin keys)
   */
  async getOwnerAddress(): Promise<string> {
    await this.initializationPromise;
    if (!this.signer) {
      throw new Error("No signer available. Connect a wallet first.");
    }
    return await this.signer.getAddress();
  }

  async getCreationFee(): Promise<bigint> {
    await this.initializationPromise;
    return await this.factory!.creationFee();
  }

  async createWallet(
    vaultId: Uint8Array,
    quipSigner: QuipSigner
  ): Promise<QuipWalletClient> {
    await this.initializationPromise;

    // Bind vaultId to signer
    const userWalletAddress = await this.signer!.getAddress();
    const creationFee = await this.getCreationFee();

    // Check if wallet already exists
    const existingWalletAddress = await this.factory!.quips(
      userWalletAddress,
      vaultId
    );
    if (existingWalletAddress !== ethers.ZeroAddress) {
      throw new Error(`Wallet already exists for vault ID ${vaultId}`);
    }

    const pqKeyPair = quipSigner.generateKeyPair(vaultId);
    const tx = await this.factory!.depositToWinternitz(
      vaultId,
      userWalletAddress,
      pqKeyPair.publicKey,
      { value: creationFee }
    );
    const receipt = await tx.wait();
    const event = receipt!.logs[0]; // QuipCreated is the first and only event
    const newWalletAddress = ethers.getAddress(`0x${event.data.slice(-40)}`);
    const newWalletContract = await QuipWallet__factory.connect(
      newWalletAddress,
      this.signer!
    );
    return new QuipWalletClient(quipSigner, vaultId, newWalletContract);
  }

  async getVault(
    vaultId: Uint8Array,
    quipSigner: QuipSigner
  ): Promise<QuipWalletClient> {
    await this.initializationPromise;
    const walletAddress = await this.factory!.quips(
      await this.signer!.getAddress(),
      vaultId
    );
    if (walletAddress === ethers.ZeroAddress) {
      throw new Error(`No wallet found for vault ID ${vaultId}`);
    }
    const walletContract = await QuipWallet__factory.connect(
      walletAddress,
      this.signer!
    );
    const client = new QuipWalletClient(quipSigner, vaultId, walletContract);
    // Check if we have the right signer
    const curPqOwner = await client.getPqOwner();
    const curSeed = Buffer.from(curPqOwner.publicSeed.replace("0x", ""), "hex");
    const curPubKeyHash = Buffer.from(
      curPqOwner.publicKeyHash.replace("0x", ""),
      "hex"
    );
    const keypair = quipSigner.recoverKeyPair(vaultId, curSeed);
    if (
      !Buffer.from(keypair.publicKey.publicKeyHash).equals(
        Buffer.from(curPubKeyHash)
      )
    ) {
      throw new Error("Invalid signer for this wallet");
    }
    return client;
  }

  async getVaultAddress(vaultId: Uint8Array): Promise<string> {
    await this.initializationPromise;

    const quipFactoryAddress = await this.factory!.getAddress();
    const signerAddress = await this.signer!.getAddress();
    const wotsLibraryAddress = await this.factory!.wotsLibrary();

    return computeVaultAddress(
      signerAddress,
      vaultId,
      wotsLibraryAddress,
      quipFactoryAddress
    );
  }

  async getVaults(): Promise<Map<string, string>> {
    await this.initializationPromise;
    if (!this.signer) {
      throw new Error("No signer available. Connect a wallet first.");
    }

    const signerAddress = await this.signer.getAddress();
    const vaultMap = new Map<string, string>();

    // Start from index 0 and keep trying until we hit an error
    let index = 0;
    while (true) {
      try {
        const vaultId = await this.factory!.vaultIds(signerAddress, index);
        const walletAddress = await this.factory!.quips(signerAddress, vaultId);
        if (walletAddress === ethers.ZeroAddress) {
          throw new Error(`Invalid contract state for vault ID ${vaultId}`);
        }
        vaultMap.set(ethers.hexlify(vaultId), walletAddress);
        index++;
      } catch {
        // We've reached the end of the array
        break;
      }
    }

    return vaultMap;
  }
}
