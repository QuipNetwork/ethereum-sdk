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
  type Hash,
  type PublicClient,
  type WalletClient,
  type TransactionReceipt,
  type EIP1193Provider,
  createPublicClient,
  createWalletClient,
  custom,
  encodePacked,
  hexToBytes,
  toHex,
  zeroAddress,
  parseEventLogs,
} from "viem";

import { quipFactoryAbi, quipWalletAbi } from "./contracts.js";
import {
  computeVaultAddress,
  getNetworkAddresses,
  CHAIN_IDS,
} from "./addresses.js";

import { WOTSPlus } from "@quip.network/hashsigs";
import { keccak_256 } from "@noble/hashes/sha3";
import { randomBytes } from "@noble/ciphers/webcrypto";

// Re-export ABIs
export { deployerAbi, quipFactoryAbi, quipWalletAbi } from "./contracts.js";

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

/**
 * Convert a WinternitzPublicKey (Uint8Array) to the hex tuple format expected by contract calls.
 */
function pubkeyToHex(pk: WinternitzPublicKey): {
  publicSeed: Hex;
  publicKeyHash: Hex;
} {
  return {
    publicSeed: toHex(pk.publicSeed),
    publicKeyHash: toHex(pk.publicKeyHash),
  };
}

/**
 * Convert WOTS+ signature (Uint8Array[]) to hex tuple for contract calls.
 * The ABI expects bytes32[67], so we cast to the fixed-length tuple type.
 */
type Bytes32Tuple67 = readonly [
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex, Hex,
  Hex, Hex, Hex, Hex, Hex, Hex, Hex,
];

function sigToHex(sig: Uint8Array[]): Bytes32Tuple67 {
  return sig.map((el) => toHex(el, { size: 32 })) as unknown as Bytes32Tuple67;
}

export class QuipWalletClient {
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private walletAddress: Address;
  private account: Address;
  private quipSigner: QuipSigner;
  private vaultId: Uint8Array;

  constructor(
    quipSigner: QuipSigner,
    vaultId: Uint8Array,
    walletAddress: Address,
    publicClient: PublicClient,
    walletClient: WalletClient,
    account: Address
  ) {
    this.walletAddress = walletAddress;
    this.vaultId = vaultId;
    this.quipSigner = quipSigner;
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.account = account;
  }

  async getPqOwner() {
    const [publicSeed, publicKeyHash] =
      await this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "pqOwner",
      });
    return { publicSeed, publicKeyHash };
  }

  async getAddress(): Promise<Address> {
    return this.walletAddress;
  }

  async getTransferFee(): Promise<bigint> {
    return await this.publicClient.readContract({
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "getTransferFee",
    });
  }

  async getExecuteFee(): Promise<bigint> {
    return await this.publicClient.readContract({
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "getExecuteFee",
    });
  }

  async transferWithWinternitz(
    to: Address,
    value: bigint,
    options: { gasLimit?: bigint } = {}
  ): Promise<TransactionReceipt> {
    const nextPqOwner = this.quipSigner.generateKeyPair(this.vaultId);
    const currentPqOwner = await this.getPqOwner();
    const publicSeed = hexToBytes(currentPqOwner.publicSeed);
    const transferFee = await this.getTransferFee();

    const packedMessageData = encodePacked(
      ["bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256"],
      [
        currentPqOwner.publicSeed,
        currentPqOwner.publicKeyHash,
        toHex(nextPqOwner.publicKey.publicSeed),
        toHex(nextPqOwner.publicKey.publicKeyHash),
        to,
        value,
      ]
    );

    const messageHash = keccak_256(hexToBytes(packedMessageData));
    const pqSig = this.quipSigner.sign(messageHash, this.vaultId, publicSeed);

    const hash = await this.walletClient.writeContract({
      chain: null,
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "transferWithWinternitz",
      args: [
        pubkeyToHex(nextPqOwner.publicKey),
        { elements: sigToHex(pqSig) },
        to,
        value,
      ],
      value: transferFee,
      account: this.account,
      ...(options.gasLimit && { gas: options.gasLimit }),
    });

    return await this.publicClient.waitForTransactionReceipt({ hash });
  }

  async executeWithWinternitz(
    target: Address,
    opdata: Hex,
    options: {
      gasLimit?: bigint;
      value?: bigint;
    } = {}
  ): Promise<TransactionReceipt> {
    const nextPqOwner = this.quipSigner.generateKeyPair(this.vaultId);
    const currentPqOwner = await this.getPqOwner();
    const publicSeed = hexToBytes(currentPqOwner.publicSeed);
    const executeFee =
      (await this.getExecuteFee()) + (options.value ?? 0n);

    const packedMessageData = encodePacked(
      ["bytes32", "bytes32", "bytes32", "bytes32", "address", "bytes"],
      [
        currentPqOwner.publicSeed,
        currentPqOwner.publicKeyHash,
        toHex(nextPqOwner.publicKey.publicSeed),
        toHex(nextPqOwner.publicKey.publicKeyHash),
        target,
        opdata,
      ]
    );

    const messageHash = keccak_256(hexToBytes(packedMessageData));
    const pqSig = this.quipSigner.sign(messageHash, this.vaultId, publicSeed);

    let gas: bigint | undefined;
    try {
      const estimatedGas = await this.publicClient.estimateContractGas({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "executeWithWinternitz",
        args: [
          pubkeyToHex(nextPqOwner.publicKey),
          { elements: sigToHex(pqSig) },
          target,
          opdata,
        ],
        value: executeFee,
        account: this.account,
      });
      gas = (estimatedGas * 120n) / 100n; // 20% buffer
    } catch (error: any) {
      console.error("Gas estimation failed:");
      console.error("Target:", target);
      console.error("Execute fee:", executeFee.toString());
      if (error.reason) {
        console.error("Revert reason:", error.reason);
      }
      console.error(`Gas estimation failed: ${error.message || error}`);
    }

    if (options.gasLimit) {
      gas = options.gasLimit;
    }

    const hash = await this.walletClient.writeContract({
      chain: null,
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "executeWithWinternitz",
      args: [
        pubkeyToHex(nextPqOwner.publicKey),
        { elements: sigToHex(pqSig) },
        target,
        opdata,
      ],
      value: executeFee,
      account: this.account,
      ...(gas && { gas }),
    });

    return await this.publicClient.waitForTransactionReceipt({ hash });
  }
}

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
    quipSigner: QuipSigner
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

    const hash = await this.walletClient.writeContract({
      chain: null,
      address: this.factoryAddress!,
      abi: quipFactoryAbi,
      functionName: "depositToWinternitz",
      args: [vaultIdHex, this.account!, pubkeyToHex(pqKeyPair.publicKey)],
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
      this.account!
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
      this.account!
    );

    // Check if we have the right signer
    const curPqOwner = await client.getPqOwner();
    const curSeed = hexToBytes(curPqOwner.publicSeed);
    const curPubKeyHash = hexToBytes(curPqOwner.publicKeyHash);
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

  async getVaultAddress(vaultId: Uint8Array): Promise<Address> {
    await this.initializationPromise;

    const wotsLibraryAddress = await this.publicClient.readContract({
      address: this.factoryAddress!,
      abi: quipFactoryAbi,
      functionName: "wotsLibrary",
    });

    return computeVaultAddress(
      this.account!,
      toHex(vaultId),
      wotsLibraryAddress,
      this.factoryAddress!
    );
  }

  async getVaults(): Promise<Map<string, Address>> {
    await this.initializationPromise;
    if (!this.account) {
      throw new Error("No account available. Connect a wallet first.");
    }

    const vaultMap = new Map<string, Address>();

    // Start from index 0 and keep trying until we hit an error
    let index = 0;
    while (true) {
      try {
        const vaultId = await this.publicClient.readContract({
          address: this.factoryAddress!,
          abi: quipFactoryAbi,
          functionName: "vaultIds",
          args: [this.account, BigInt(index)],
        });
        const walletAddress = await this.publicClient.readContract({
          address: this.factoryAddress!,
          abi: quipFactoryAbi,
          functionName: "quips",
          args: [this.account, vaultId],
        });
        if (walletAddress === zeroAddress) {
          throw new Error(`Invalid contract state for vault ID ${vaultId}`);
        }
        vaultMap.set(vaultId, walletAddress);
        index++;
      } catch {
        // We've reached the end of the array
        break;
      }
    }

    return vaultMap;
  }
}
