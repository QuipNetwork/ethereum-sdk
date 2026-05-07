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
import { withDecodedError } from "./internal/decodeError.js";
import { tryMulticall } from "./internal/multicall.js";
import {
  type TxOptions,
  type PreparedTx,
  type ContractCallParams,
  prepareTx,
} from "./gas.js";

/// 32-byte WOTS+ key tuple as returned by the contract's `keyAt` and stored
/// in the SDK's read-aggregator outputs. Same shape as the on-chain
/// `WOTSPlus.WinternitzAddress` struct.
export interface WinternitzAddress {
  publicSeed: Hex;
  publicKeyHash: Hex;
}

/// Aggregated wallet state, one round-trip's worth of view-method reads.
/// Keysets are read in a follow-up batch sized by the counts in the first
/// round.
export interface WalletState {
  owner: Address;
  factory: Address;
  entryPoint: Address;
  executeFee: bigint;
  deposit: bigint;
  keyCounts: { transaction: bigint; recovery: bigint; verification: bigint };
  transactionKeys: WinternitzAddress[];
  recoveryKeys: WinternitzAddress[];
  verificationKeys: WinternitzAddress[];
}

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
    const [publicSeed, publicKeyHash] = await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "pqOwner",
      })
    );
    return { publicSeed, publicKeyHash };
  }

  async getAddress(): Promise<Address> {
    return this.walletAddress;
  }

  async getTransferFee(): Promise<bigint> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "getTransferFee",
      })
    );
  }

  async getExecuteFee(): Promise<bigint> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "getExecuteFee",
      })
    );
  }

  /// Run prepareTx + writeContract + waitForTransactionReceipt, using the
  /// new gas/simulation pipeline. All write methods on this client funnel
  /// through here so they share one error-handling path.
  private async executeWrite(
    contractCall: ContractCallParams,
    totalValue: bigint,
    opts: TxOptions
  ): Promise<TransactionReceipt> {
    const prepared = await prepareTx({
      publicClient: this.publicClient,
      contractParams: contractCall,
      totalValue,
      opts,
    });

    const writeParams = {
      chain: null,
      ...contractCall,
      gas: prepared.gas,
      ...prepared.fees,
      ...(prepared.nonce !== undefined && { nonce: prepared.nonce }),
    } as Parameters<WalletClient["writeContract"]>[0];

    const hash = await withDecodedError(
      this.walletClient.writeContract(writeParams)
    );

    return await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /// Public estimation entrypoint. Builds the same `prepareTx` call the
  /// write methods use, but stops short of `writeContract`. Useful for UI
  /// pre-flight ("show me the gas this would burn").
  async estimateExecute(
    target: Address,
    opdata: Hex,
    opts: TxOptions & { value?: bigint } = {}
  ): Promise<PreparedTx> {
    const built = await this.buildExecuteCall(target, opdata, opts.value ?? 0n);
    return prepareTx({
      publicClient: this.publicClient,
      contractParams: built.contractCall,
      totalValue: built.totalValue,
      opts,
    });
  }

  async estimateTransfer(
    to: Address,
    value: bigint,
    opts: TxOptions = {}
  ): Promise<PreparedTx> {
    const built = await this.buildTransferCall(to, value);
    return prepareTx({
      publicClient: this.publicClient,
      contractParams: built.contractCall,
      totalValue: built.totalValue,
      opts,
    });
  }

  /// Build the message + sign + assemble contract-call params for a transfer.
  /// Lifted into its own method so `transferWithWinternitz` and
  /// `estimateTransfer` share the same signing path (each call burns a
  /// fresh next-pqOwner key, so they cannot share a single signature, but
  /// the call-construction logic is identical).
  private async buildTransferCall(
    to: Address,
    value: bigint
  ): Promise<{ contractCall: ContractCallParams; totalValue: bigint }> {
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

    const contractCall: ContractCallParams = {
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
    };

    // The wallet pays both the fee and `value` in the same write —
    // `transferFee` is `msg.value` to the contract; the contract forwards
    // `value` to `to`. The caller (`account`) only needs to fund `transferFee`
    // since the wallet contract holds the recipient ETH.
    return { contractCall, totalValue: transferFee };
  }

  private async buildExecuteCall(
    target: Address,
    opdata: Hex,
    innerValue: bigint
  ): Promise<{ contractCall: ContractCallParams; totalValue: bigint }> {
    const nextPqOwner = this.quipSigner.generateKeyPair(this.vaultId);
    const currentPqOwner = await this.getPqOwner();
    const publicSeed = hexToBytes(currentPqOwner.publicSeed);
    const executeFee = (await this.getExecuteFee()) + innerValue;

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

    const contractCall: ContractCallParams = {
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
    };

    return { contractCall, totalValue: executeFee };
  }

  async transferWithWinternitz(
    to: Address,
    value: bigint,
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const built = await this.buildTransferCall(to, value);
    return this.executeWrite(built.contractCall, built.totalValue, opts);
  }

  async executeWithWinternitz(
    target: Address,
    opdata: Hex,
    opts: TxOptions & { value?: bigint } = {}
  ): Promise<TransactionReceipt> {
    const built = await this.buildExecuteCall(target, opdata, opts.value ?? 0n);
    return this.executeWrite(built.contractCall, built.totalValue, opts);
  }

  async changePqOwner(opts: TxOptions = {}): Promise<TransactionReceipt> {
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

    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "changePqOwner",
      args: [
        pubkeyToHex(nextPqOwner.publicKey),
        { elements: sigToHex(pqSig) },
      ],
      account: this.account,
    };

    return this.executeWrite(contractCall, 0n, opts);
  }

  async recoverWallet(
    recoveryPublicSeed: Uint8Array,
    opts: TxOptions = {}
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

    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "recoverWallet",
      args: [
        pubkeyToHex(recoveryKeyPair.publicKey),
        pubkeyToHex(newPqOwner.publicKey),
        { elements: sigToHex(pqSig) },
      ],
      account: this.account,
    };

    return this.executeWrite(contractCall, 0n, opts);
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
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const { nextPqOwner, pqSig, recoveryKeysHex } =
      await this.signRecoveryKeysMessage(newRecoveryKeys);

    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "addRecoveryKeys",
      args: [
        pubkeyToHex(nextPqOwner.publicKey),
        { elements: sigToHex(pqSig) },
        recoveryKeysHex,
      ],
      account: this.account,
    };

    return this.executeWrite(contractCall, 0n, opts);
  }

  async replenishRecoveryKeys(
    newRecoveryKeys: WinternitzPublicKey[],
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const { nextPqOwner, pqSig, recoveryKeysHex } =
      await this.signRecoveryKeysMessage(newRecoveryKeys);

    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "replenishRecoveryKeys",
      args: [
        pubkeyToHex(nextPqOwner.publicKey),
        { elements: sigToHex(pqSig) },
        recoveryKeysHex,
      ],
      account: this.account,
    };

    return this.executeWrite(contractCall, 0n, opts);
  }

  async keyCount(kind: KeyType): Promise<bigint> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "keyCount",
        args: [kind],
      })
    );
  }

  async keyAt(
    kind: KeyType,
    index: bigint
  ): Promise<{ publicSeed: Hex; publicKeyHash: Hex }> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "keyAt",
        args: [kind, index],
      })
    );
  }

  async isKey(
    kind: KeyType,
    key: { publicSeed: Hex; publicKeyHash: Hex }
  ): Promise<boolean> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "isKey",
        args: [kind, key],
      })
    );
  }

  /// Return every key in `kind`'s set, ordered by index. Two RPC round-trips
  /// at most: one for `keyCount`, one for the multicalled `keyAt` reads
  /// (or sequential fallback on chains without Multicall3).
  async getKeyset(
    kind: KeyType,
    opts?: { forceSequential?: boolean }
  ): Promise<WinternitzAddress[]> {
    const count = await this.keyCount(kind);
    if (count === 0n) return [];

    const calls = Array.from({ length: Number(count) }, (_, i) => ({
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "keyAt" as const,
      args: [kind, BigInt(i)] as const,
    }));

    const results = await tryMulticall(this.publicClient, calls, {
      chainId: this.chainId,
      ...(opts?.forceSequential && { forceSequential: true }),
    });

    const keys: WinternitzAddress[] = [];
    for (const r of results) {
      if (r.status === "success") {
        keys.push(r.result as WinternitzAddress);
      }
    }
    return keys;
  }

  /// Aggregate every wallet view-method into a structured snapshot. Two
  /// multicalls: the first for scalar fields + key counts, the second for
  /// every key in every keyset. Single round-trip per phase on chains with
  /// Multicall3; sequential fallback otherwise.
  async getWalletState(
    opts?: { forceSequential?: boolean }
  ): Promise<WalletState> {
    const scalarCalls = [
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "owner" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "quipFactory" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "entryPoint" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "getExecuteFee" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "getDeposit" as const },
      {
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "keyCount" as const,
        args: [KeyType.Transaction] as const,
      },
      {
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "keyCount" as const,
        args: [KeyType.Recovery] as const,
      },
      {
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "keyCount" as const,
        args: [KeyType.Verification] as const,
      },
    ];

    const scalars = await tryMulticall(this.publicClient, scalarCalls, {
      chainId: this.chainId,
      ...(opts?.forceSequential && { forceSequential: true }),
    });

    const expect = <T,>(r: typeof scalars[number], label: string): T => {
      if (r.status === "failure") {
        throw r.error instanceof Error
          ? r.error
          : new Error(`${label} read failed`);
      }
      return r.result as T;
    };

    const owner = expect<Address>(scalars[0], "owner");
    const factory = expect<Address>(scalars[1], "quipFactory");
    const entryPoint = expect<Address>(scalars[2], "entryPoint");
    const executeFee = expect<bigint>(scalars[3], "getExecuteFee");
    const deposit = expect<bigint>(scalars[4], "getDeposit");
    const txCount = expect<bigint>(scalars[5], "keyCount(Transaction)");
    const rcCount = expect<bigint>(scalars[6], "keyCount(Recovery)");
    const vfCount = expect<bigint>(scalars[7], "keyCount(Verification)");

    const buildKeyAtCalls = (kind: KeyType, count: bigint) =>
      Array.from({ length: Number(count) }, (_, i) => ({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "keyAt" as const,
        args: [kind, BigInt(i)] as const,
      }));

    const allKeyCalls = [
      ...buildKeyAtCalls(KeyType.Transaction, txCount),
      ...buildKeyAtCalls(KeyType.Recovery, rcCount),
      ...buildKeyAtCalls(KeyType.Verification, vfCount),
    ];

    const keyResults =
      allKeyCalls.length === 0
        ? []
        : await tryMulticall(this.publicClient, allKeyCalls, {
            chainId: this.chainId,
            ...(opts?.forceSequential && { forceSequential: true }),
          });

    const successOnly = (results: typeof keyResults): WinternitzAddress[] =>
      results
        .filter((r) => r.status === "success")
        .map((r) => r.result as WinternitzAddress);

    const txEnd = Number(txCount);
    const rcEnd = txEnd + Number(rcCount);
    const vfEnd = rcEnd + Number(vfCount);

    const transactionKeys = successOnly(keyResults.slice(0, txEnd));
    const recoveryKeys = successOnly(keyResults.slice(txEnd, rcEnd));
    const verificationKeys = successOnly(keyResults.slice(rcEnd, vfEnd));

    return {
      owner,
      factory,
      entryPoint,
      executeFee,
      deposit,
      keyCounts: { transaction: txCount, recovery: rcCount, verification: vfCount },
      transactionKeys,
      recoveryKeys,
      verificationKeys,
    };
  }
}
