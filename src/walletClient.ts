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
  type TransactionReceipt,
  encodeAbiParameters,
  encodePacked,
  hexToBytes,
  toHex,
} from "viem";

import { keccak_256 } from "@noble/hashes/sha3";

import { quipWalletAbi } from "./abi/QuipWallet.js";
import { QuipSigner, type WinternitzPublicKey } from "./signer.js";
import { pubkeyToHex, sigToHex } from "./internal/abi.js";

/// Mirrors the `IQuipWallet.KeyType` enum.
export enum KeyType {
  Transaction = 0,
  Recovery = 1,
  Verification = 2,
}

export class QuipWalletClient {
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private walletAddress: Address;
  private account: Address;
  private quipSigner: QuipSigner;
  private vaultId: Uint8Array;
  private chainId: number;

  constructor(
    quipSigner: QuipSigner,
    vaultId: Uint8Array,
    walletAddress: Address,
    publicClient: PublicClient,
    walletClient: WalletClient,
    account: Address,
    chainId: number
  ) {
    this.walletAddress = walletAddress;
    this.vaultId = vaultId;
    this.quipSigner = quipSigner;
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.account = account;
    this.chainId = chainId;
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
      ["uint256", "address", "bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256"],
      [
        BigInt(this.chainId),
        this.walletAddress,
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
      ["uint256", "address", "bytes32", "bytes32", "bytes32", "bytes32", "address", "bytes"],
      [
        BigInt(this.chainId),
        this.walletAddress,
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

    let gas: bigint;
    if (options.gasLimit) {
      gas = options.gasLimit;
    } else {
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
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Gas estimation failed for executeWithWinternitz on ${target}: ${message}`);
      }
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
      gas,
    });

    return await this.publicClient.waitForTransactionReceipt({ hash });
  }

  async changePqOwner(
    options: { gasLimit?: bigint } = {}
  ): Promise<TransactionReceipt> {
    const nextPqOwner = this.quipSigner.generateKeyPair(this.vaultId);
    const currentPqOwner = await this.getPqOwner();
    const publicSeed = hexToBytes(currentPqOwner.publicSeed);

    const packedMessageData = encodePacked(
      ["uint256", "address", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        BigInt(this.chainId),
        this.walletAddress,
        currentPqOwner.publicSeed,
        currentPqOwner.publicKeyHash,
        toHex(nextPqOwner.publicKey.publicSeed),
        toHex(nextPqOwner.publicKey.publicKeyHash),
      ]
    );

    const messageHash = keccak_256(hexToBytes(packedMessageData));
    const pqSig = this.quipSigner.sign(messageHash, this.vaultId, publicSeed);

    const hash = await this.walletClient.writeContract({
      chain: null,
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "changePqOwner",
      args: [
        pubkeyToHex(nextPqOwner.publicKey),
        { elements: sigToHex(pqSig) },
      ],
      account: this.account,
      ...(options.gasLimit && { gas: options.gasLimit }),
    });

    return await this.publicClient.waitForTransactionReceipt({ hash });
  }

  async recoverWallet(
    recoveryPublicSeed: Uint8Array,
    options: { gasLimit?: bigint } = {}
  ): Promise<TransactionReceipt> {
    const recoveryKeyPair = this.quipSigner.recoverKeyPair(this.vaultId, recoveryPublicSeed);
    const newPqOwner = this.quipSigner.generateKeyPair(this.vaultId);

    const packedMessageData = encodePacked(
      ["uint256", "address", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        BigInt(this.chainId),
        this.walletAddress,
        toHex(recoveryKeyPair.publicKey.publicSeed),
        toHex(recoveryKeyPair.publicKey.publicKeyHash),
        toHex(newPqOwner.publicKey.publicSeed),
        toHex(newPqOwner.publicKey.publicKeyHash),
      ]
    );

    const messageHash = keccak_256(hexToBytes(packedMessageData));
    const pqSig = this.quipSigner.sign(messageHash, this.vaultId, recoveryPublicSeed);

    const hash = await this.walletClient.writeContract({
      chain: null,
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "recoverWallet",
      args: [
        pubkeyToHex(recoveryKeyPair.publicKey),
        pubkeyToHex(newPqOwner.publicKey),
        { elements: sigToHex(pqSig) },
      ],
      account: this.account,
      ...(options.gasLimit && { gas: options.gasLimit }),
    });

    return await this.publicClient.waitForTransactionReceipt({ hash });
  }

  private async signRecoveryKeysMessage(
    newRecoveryKeys: WinternitzPublicKey[]
  ) {
    const nextPqOwner = this.quipSigner.generateKeyPair(this.vaultId);
    const currentPqOwner = await this.getPqOwner();
    const publicSeed = hexToBytes(currentPqOwner.publicSeed);
    const recoveryKeysHex = newRecoveryKeys.map((pk) => pubkeyToHex(pk));

    // Replicate Solidity's keccak256(abi.encode(newRecoveryKeys))
    const keysEncoded = encodeAbiParameters(
      [
        {
          type: "tuple[]",
          components: [
            { type: "bytes32", name: "publicSeed" },
            { type: "bytes32", name: "publicKeyHash" },
          ],
        },
      ],
      [recoveryKeysHex]
    );
    const keysHash = toHex(keccak_256(hexToBytes(keysEncoded)));

    const packedMessageData = encodePacked(
      ["uint256", "address", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        BigInt(this.chainId),
        this.walletAddress,
        currentPqOwner.publicSeed,
        currentPqOwner.publicKeyHash,
        toHex(nextPqOwner.publicKey.publicSeed),
        toHex(nextPqOwner.publicKey.publicKeyHash),
        keysHash as Hex,
      ]
    );

    const messageHash = keccak_256(hexToBytes(packedMessageData));
    const pqSig = this.quipSigner.sign(messageHash, this.vaultId, publicSeed);

    return { nextPqOwner, pqSig, recoveryKeysHex };
  }

  async addRecoveryKeys(
    newRecoveryKeys: WinternitzPublicKey[],
    options: { gasLimit?: bigint } = {}
  ): Promise<TransactionReceipt> {
    const { nextPqOwner, pqSig, recoveryKeysHex } =
      await this.signRecoveryKeysMessage(newRecoveryKeys);

    const hash = await this.walletClient.writeContract({
      chain: null,
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "addRecoveryKeys",
      args: [
        pubkeyToHex(nextPqOwner.publicKey),
        { elements: sigToHex(pqSig) },
        recoveryKeysHex,
      ],
      account: this.account,
      ...(options.gasLimit && { gas: options.gasLimit }),
    });

    return await this.publicClient.waitForTransactionReceipt({ hash });
  }

  async replenishRecoveryKeys(
    newRecoveryKeys: WinternitzPublicKey[],
    options: { gasLimit?: bigint } = {}
  ): Promise<TransactionReceipt> {
    const { nextPqOwner, pqSig, recoveryKeysHex } =
      await this.signRecoveryKeysMessage(newRecoveryKeys);

    const hash = await this.walletClient.writeContract({
      chain: null,
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "replenishRecoveryKeys",
      args: [
        pubkeyToHex(nextPqOwner.publicKey),
        { elements: sigToHex(pqSig) },
        recoveryKeysHex,
      ],
      account: this.account,
      ...(options.gasLimit && { gas: options.gasLimit }),
    });

    return await this.publicClient.waitForTransactionReceipt({ hash });
  }

  async keyCount(kind: KeyType): Promise<bigint> {
    return await this.publicClient.readContract({
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "keyCount",
      args: [kind],
    });
  }

  async keyAt(
    kind: KeyType,
    index: bigint
  ): Promise<{ publicSeed: Hex; publicKeyHash: Hex }> {
    return await this.publicClient.readContract({
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "keyAt",
      args: [kind, index],
    });
  }

  async isKey(
    kind: KeyType,
    key: { publicSeed: Hex; publicKeyHash: Hex }
  ): Promise<boolean> {
    return await this.publicClient.readContract({
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "isKey",
      args: [kind, key],
    });
  }
}
