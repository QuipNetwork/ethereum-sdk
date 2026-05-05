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
import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  type EIP1193Provider,
  createPublicClient,
  createWalletClient,
  custom,
  hexToBytes,
  toHex,
  zeroAddress,
  parseEventLogs,
} from "viem";

import { equalBytes } from "@noble/ciphers/utils";

import { quipFactoryAbi } from "./abi/QuipFactory.js";
import {
  getVaultAddress,
  getNetworkAddresses,
  CHAIN_IDS,
} from "./addresses.js";
import { QuipSigner, type WinternitzPublicKey } from "./signer.js";
import { QuipWalletClient } from "./walletClient.js";
import { pubkeyToHex } from "./internal/abi.js";

export class QuipClient {
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private account?: Address;
  private factoryAddress?: Address;
  private chainId?: number;
  private initializationPromise: Promise<void>;

  /**
   * Create a QuipClient instance
   * Works with any EIP-1193 compatible provider
   *
   * @param provider - An EIP-1193 compatible provider
   */
  constructor(provider: EIP1193Provider) {
    const transport = custom(provider);
    this.publicClient = createPublicClient({ transport });
    this.walletClient = createWalletClient({ transport });
    this.initializationPromise = this.initialize();
  }

  /**
   * Factory method for creating QuipClient instances
   * Provides a cleaner async initialization pattern
   */
  static async create(
    provider: EIP1193Provider
  ): Promise<QuipClient> {
    const client = new QuipClient(provider);
    await client.initializationPromise;
    return client;
  }

  private async initialize() {
    await this.detectNetwork();
    await this.setAccount();
    await this.setQuipFactory();
  }

  private async setAccount() {
    const [address] = await this.walletClient.getAddresses();
    this.account = address;
  }

  private async detectNetwork() {
    this.chainId = await this.publicClient.getChainId();
  }

  private async setQuipFactory() {
    const addresses = getNetworkAddresses(this.chainId);
    this.factoryAddress = addresses.QuipFactory;
  }

  /**
   * Get the current chain ID
   */
  getChainId(): number {
    if (!this.chainId) {
      throw new Error(
        "Client not initialized. Call await client.initializationPromise first."
      );
    }
    return this.chainId;
  }

  /**
   * Check if connected to MIDL network
   */
  isMidlNetwork(): boolean {
    return this.chainId === CHAIN_IDS.MIDL_TESTNET;
  }

  /**
   * Get the connected wallet's owner address
   */
  async getOwnerAddress(): Promise<Address> {
    await this.initializationPromise;
    if (!this.account) {
      throw new Error("No account available. Connect a wallet first.");
    }
    return this.account;
  }

  async getCreationFee(): Promise<bigint> {
    await this.initializationPromise;
    return await this.publicClient.readContract({
      address: this.factoryAddress!,
      abi: quipFactoryAbi,
      functionName: "creationFee",
    });
  }

  async createWallet(
    vaultId: Uint8Array,
    quipSigner: QuipSigner,
    recoveryKeys: WinternitzPublicKey[] = []
  ): Promise<QuipWalletClient> {
    await this.initializationPromise;

    const vaultIdHex = toHex(vaultId) as Hex;
    const creationFee = await this.getCreationFee();

    // Check if wallet already exists
    const existingWalletAddress = await this.publicClient.readContract({
      address: this.factoryAddress!,
      abi: quipFactoryAbi,
      functionName: "quips",
      args: [this.account!, vaultIdHex],
    });

    if (existingWalletAddress !== zeroAddress) {
      throw new Error(`Wallet already exists for vault ID ${vaultIdHex}`);
    }

    const pqKeyPair = quipSigner.generateKeyPair(vaultId);
    const recoveryKeysHex = recoveryKeys.map((pk) => pubkeyToHex(pk));

    const hash = await this.walletClient.writeContract({
      chain: null,
      address: this.factoryAddress!,
      abi: quipFactoryAbi,
      functionName: "depositToWinternitz",
      args: [vaultIdHex, this.account!, pubkeyToHex(pqKeyPair.publicKey), recoveryKeysHex],
      value: creationFee,
      account: this.account!,
    });

    const receipt = await this.publicClient.waitForTransactionReceipt({
      hash,
    });

    const logs = parseEventLogs({
      abi: quipFactoryAbi,
      logs: receipt.logs,
      eventName: "QuipCreated",
    });
    const newWalletAddress = logs[0].args.quip;

    return new QuipWalletClient(
      quipSigner,
      vaultId,
      newWalletAddress,
      this.publicClient,
      this.walletClient,
      this.account!,
      this.chainId!
    );
  }

  async getVault(
    vaultId: Uint8Array,
    quipSigner: QuipSigner
  ): Promise<QuipWalletClient> {
    await this.initializationPromise;

    const vaultIdHex = toHex(vaultId) as Hex;
    const walletAddress = await this.publicClient.readContract({
      address: this.factoryAddress!,
      abi: quipFactoryAbi,
      functionName: "quips",
      args: [this.account!, vaultIdHex],
    });

    if (walletAddress === zeroAddress) {
      throw new Error(`No wallet found for vault ID ${vaultIdHex}`);
    }

    const client = new QuipWalletClient(
      quipSigner,
      vaultId,
      walletAddress,
      this.publicClient,
      this.walletClient,
      this.account!,
      this.chainId!
    );

    // Check if we have the right signer
    const curPqOwner = await client.getPqOwner();
    const curSeed = hexToBytes(curPqOwner.publicSeed);
    const curPubKeyHash = hexToBytes(curPqOwner.publicKeyHash);
    const keypair = quipSigner.recoverKeyPair(vaultId, curSeed);
    if (!equalBytes(keypair.publicKey.publicKeyHash, curPubKeyHash)) {
      throw new Error("Invalid signer for this wallet");
    }
    return client;
  }

  async getVaultAddress(vaultId: Uint8Array): Promise<Address> {
    await this.initializationPromise;
    return getVaultAddress(toHex(vaultId), this.chainId);
  }

  async getVaults(): Promise<Map<string, Address>> {
    await this.initializationPromise;
    if (!this.account) {
      throw new Error("No account available. Connect a wallet first.");
    }

    const vaultMap = new Map<string, Address>();
    const batchSize = 50;
    let offset = 0;

    while (true) {
      // Batch-read vaultIds
      const vaultIdCalls = Array.from({ length: batchSize }, (_, i) => ({
        address: this.factoryAddress!,
        abi: quipFactoryAbi,
        functionName: "vaultIds" as const,
        args: [this.account!, BigInt(offset + i)] as const,
      }));

      let vaultIdResults: { status: "success" | "failure"; result?: Hex }[];
      try {
        vaultIdResults = (await this.publicClient.multicall({
          contracts: vaultIdCalls,
          allowFailure: true,
        })) as { status: "success" | "failure"; result?: Hex }[];
      } catch {
        // Multicall3 not available — fall back to sequential reads
        return this.getVaultsSequential();
      }

      const validVaultIds: Hex[] = [];
      for (const r of vaultIdResults) {
        if (r.status === "success" && r.result) {
          validVaultIds.push(r.result);
        } else {
          break; // past end of array
        }
      }

      if (validVaultIds.length === 0) break;

      // Batch-read quips addresses for all valid vault IDs
      const quipsCalls = validVaultIds.map((vaultId) => ({
        address: this.factoryAddress!,
        abi: quipFactoryAbi,
        functionName: "quips" as const,
        args: [this.account!, vaultId] as const,
      }));

      const quipsResults = (await this.publicClient.multicall({
        contracts: quipsCalls,
        allowFailure: true,
      })) as { status: "success" | "failure"; result?: Address }[];

      for (let i = 0; i < validVaultIds.length; i++) {
        const r = quipsResults[i];
        if (r.status === "success" && r.result && r.result !== zeroAddress) {
          vaultMap.set(validVaultIds[i], r.result);
        }
      }

      if (validVaultIds.length < batchSize) break;
      offset += batchSize;
    }

    return vaultMap;
  }

  /**
   * Sequential fallback for chains without Multicall3 (e.g. MIDL testnet).
   */
  private async getVaultsSequential(): Promise<Map<string, Address>> {
    const vaultMap = new Map<string, Address>();
    let index = 0;
    while (true) {
      try {
        const vaultId = await this.publicClient.readContract({
          address: this.factoryAddress!,
          abi: quipFactoryAbi,
          functionName: "vaultIds",
          args: [this.account!, BigInt(index)],
        });
        const walletAddress = await this.publicClient.readContract({
          address: this.factoryAddress!,
          abi: quipFactoryAbi,
          functionName: "quips",
          args: [this.account!, vaultId],
        });
        if (walletAddress === zeroAddress) break;
        vaultMap.set(vaultId, walletAddress);
        index++;
      } catch {
        break;
      }
    }
    return vaultMap;
  }
}
