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
  hexToBytes,
  toHex,
} from "viem";

import { quipWalletAbi } from "./abi/QuipWallet.js";
import { QuipSigner, type WinternitzPublicKey } from "./signer.js";
import { pubkeyToHex } from "./internal/abi.js";
import { withDecodedError } from "./internal/decodeError.js";
import { tryMulticall } from "./internal/multicall.js";
import {
  type TxOptions,
  type PreparedTx,
  type ContractCallParams,
  prepareTx,
} from "./gas.js";
import { RefreshTransactionForbiddenError } from "./errors.js";
import {
  type WinternitzAddress as CodecAddress,
  type WinternitzElements,
  encodeExecute,
  encodeKeyManagement,
  encodeReplaceKeyAt,
  encodeWithdrawDeposit,
  encodeRecoverWallet,
  executeDigest,
  keysetDigest,
  keysHash as codecKeysHash,
  opdataHash as codecOpdataHash,
  replaceKeyAtDigest,
  withdrawDepositDigest,
  recoverWalletDigest,
} from "./wotsCodec.js";

/// 32-byte WOTS+ key tuple as returned by the contract's `keyAt` and stored
/// in the SDK's read-aggregator outputs.
export interface WinternitzAddress {
  publicSeed: Hex;
  publicKeyHash: Hex;
}

/// Per-call override for which transaction-keyset entry the SDK signs
/// with. Threaded through every wallet write that consumes a transaction
/// key (execute, withdrawDeposit, addKeys, refreshKeys, replaceKeyAt).
///
/// Default behavior (no override) signs with `keyAt(Transaction, 0)` — the
/// head of the set. Override when:
///   1. Multiple operations are in flight concurrently. WOTS+ is a one-time
///      signature scheme: every in-flight op MUST use a distinct key, or
///      the second broadcast double-uses the first key and forfeits the
///      forgery-resistance property.
///   2. Resubmitting a previously-broadcast op after a mempool eviction.
///      Resubmit the IDENTICAL signed payload (same key) — do NOT sign a
///      new message with that key. If the message must change, pick a
///      different key from the keyset.
///   3. Execution of a call failed and need to select/used a different key
///      than previous key used.
///
/// The supplied address must be a member of the transaction keyset; the
/// contract will revert `UnknownKey` (typed `UnknownKeyError` here) if
/// not. The SDK does NOT pre-validate to avoid an extra RPC per write.
export interface TransactionKeyOptions {
  signWithKey?: WinternitzAddress;
}

export interface WalletState {
  owner: Address;
  factory: Address;
  entryPoint: Address;
  executeFee: bigint;
  deposit: bigint;
  disasterRecoveryKey: WinternitzAddress;
  ownershipKey: WinternitzAddress;
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

  async getAddress(): Promise<Address> {
    return this.walletAddress;
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

  /// Current `disasterRecoveryKey` — the WOTS+ public key that authorizes
  /// `saveWallet`. Stored at a fixed slot on chain and rotates on use.
  async getDisasterRecoveryKey(): Promise<WinternitzAddress> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "getDisasterRecoveryKey",
      })
    );
  }

  /// Current `ownershipKey` — the WOTS+ public key that authorizes
  /// `transferOwnership` / `completeOwnershipHandover`. Stored at a fixed
  /// slot on chain and rotates on use.
  async getOwnershipKey(): Promise<WinternitzAddress> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "getOwnershipKey",
      })
    );
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
  ): Promise<WinternitzAddress> {
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
    key: WinternitzAddress
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

  /// Read the head transaction key — `keyAt(Transaction, 0)`, the slot the
  /// SDK signs with by default. Note that this is just whichever key
  /// happens to occupy index 0 right now; the EnumerableSet's swap-pop
  /// rotation can shuffle which key sits there. Callers that need a
  /// specific key — e.g. running multiple ops concurrently and avoiding
  /// double-signing — should call `getKeyset(Transaction)` and pass the
  /// chosen key as `signWithKey` on the relevant write method.
  async getHeadTransactionKey(): Promise<WinternitzAddress> {
    return this.keyAt(KeyType.Transaction, 0n);
  }

  /// Read every key in `kind`'s set, ordered by index. Two RPC round-trips
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

  async getWalletState(
    opts?: { forceSequential?: boolean }
  ): Promise<WalletState> {
    const scalarCalls = [
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "owner" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "quipFactory" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "entryPoint" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "getExecuteFee" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "getDeposit" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "getDisasterRecoveryKey" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "getOwnershipKey" as const },
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
    const disasterRecoveryKey = expect<WinternitzAddress>(
      scalars[5],
      "getDisasterRecoveryKey"
    );
    const ownershipKey = expect<WinternitzAddress>(
      scalars[6],
      "getOwnershipKey"
    );
    const txCount = expect<bigint>(scalars[7], "keyCount(Transaction)");
    const rcCount = expect<bigint>(scalars[8], "keyCount(Recovery)");
    const vfCount = expect<bigint>(scalars[9], "keyCount(Verification)");

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
      disasterRecoveryKey,
      ownershipKey,
      keyCounts: { transaction: txCount, recovery: rcCount, verification: vfCount },
      transactionKeys,
      recoveryKeys,
      verificationKeys,
    };
  }

  /// Funnel for every payload-based write. Each write method builds its
  /// codec payload + contract call params, then delegates to this helper for
  /// simulation, gas estimation, sending, and receipt waiting.
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
    return this.submit(contractCall, prepared);
  }

  private async submit(
    contractCall: ContractCallParams,
    prepared: PreparedTx
  ): Promise<TransactionReceipt> {
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

  /// Sign a digest with the recovered private key for `currentKey`. The
  /// SDK's `QuipSigner` regenerates the keypair from `(quantumSecret, vaultId,
  /// publicSeed)` deterministically.
  private signWith(
    currentSeedBytes: Uint8Array,
    digest: Hex
  ): WinternitzElements {
    const sig = this.quipSigner.sign(
      hexToBytes(digest),
      this.vaultId,
      currentSeedBytes
    );
    return {
      elements: sig.map((el) => toHex(el, { size: 32 })),
    };
  }

  /// Pick a transaction key to sign with (caller-supplied or the head of
  /// the set), generate a fresh next key, and recover both as
  /// codec-shaped tuples plus the bytes-form seed the signer needs.
  private async pickTransactionKeyPair(
    keyOpts?: TransactionKeyOptions
  ): Promise<{
    currentKey: CodecAddress;
    nextKey: CodecAddress;
    currentSeedBytes: Uint8Array;
  }> {
    const current =
      keyOpts?.signWithKey ?? (await this.getHeadTransactionKey());
    const next = this.quipSigner.generateKeyPair(this.vaultId);
    return {
      currentKey: current,
      nextKey: {
        publicSeed: toHex(next.publicKey.publicSeed),
        publicKeyHash: toHex(next.publicKey.publicKeyHash),
      },
      currentSeedBytes: hexToBytes(current.publicSeed),
    };
  }

  private async buildExecutePayload(
    target: Address,
    value: bigint,
    data: Hex,
    keyOpts?: TransactionKeyOptions
  ): Promise<{ payload: Hex; totalValue: bigint }> {
    const { currentKey, nextKey, currentSeedBytes } =
      await this.pickTransactionKeyPair(keyOpts);
    const fee = await this.getExecuteFee();
    const totalValue = fee + value;

    const digest = executeDigest(
      this.walletAddress,
      BigInt(this.chainId),
      currentKey.publicSeed,
      currentKey.publicKeyHash,
      nextKey.publicSeed,
      nextKey.publicKeyHash,
      target,
      value,
      codecOpdataHash(data),
      fee
    );
    const pqSig = this.signWith(currentSeedBytes, digest);
    const payload = encodeExecute(currentKey, nextKey, pqSig, target, value, data);
    return { payload, totalValue };
  }

  /// Codec-payload `execute(bytes)`. Replaces the legacy
  /// `transferWithWinternitz`, `executeWithWinternitz`, and `changePqOwner`
  /// — each is now `executeWithPayload(target, value, data)` with the
  /// appropriate args. ETH-only transfer = `(to, amount, "0x")`. Pure
  /// rotation = `(zeroAddr, 0n, "0x")` — fee still applies.
  async executeWithPayload(
    target: Address,
    value: bigint,
    data: Hex,
    opts: TxOptions & TransactionKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const built = await this.buildExecutePayload(target, value, data, opts);
    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "execute",
      args: [built.payload],
      value: built.totalValue,
      account: this.account,
    };
    return this.executeWrite(contractCall, built.totalValue, opts);
  }

  /// Pre-flight version: return the prepared tx (gas + fees) without sending.
  async estimateExecute(
    target: Address,
    value: bigint,
    data: Hex,
    opts: TxOptions & TransactionKeyOptions = {}
  ): Promise<PreparedTx> {
    const built = await this.buildExecutePayload(target, value, data, opts);
    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "execute",
      args: [built.payload],
      value: built.totalValue,
      account: this.account,
    };
    return prepareTx({
      publicClient: this.publicClient,
      contractParams: contractCall,
      totalValue: built.totalValue,
      opts,
    });
  }

  /// PQ-authenticated `withdrawDepositTo(bytes)` — pulls ETH from the
  /// wallet's ERC-4337 EntryPoint deposit.
  async withdrawDeposit(
    to: Address,
    amount: bigint,
    opts: TxOptions & TransactionKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const { currentKey, nextKey, currentSeedBytes } =
      await this.pickTransactionKeyPair(opts);
    const digest = withdrawDepositDigest(
      this.walletAddress,
      BigInt(this.chainId),
      currentKey.publicSeed,
      currentKey.publicKeyHash,
      nextKey.publicSeed,
      nextKey.publicKeyHash,
      to,
      amount
    );
    const pqSig = this.signWith(currentSeedBytes, digest);
    const payload = encodeWithdrawDeposit(currentKey, nextKey, pqSig, to, amount);
    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "withdrawDepositTo",
      args: [payload],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
  }

  /// Add `keys` to the `kind` keyset. Backend: `addKeys(bytes payload)`.
  async addKeys(
    kind: KeyType,
    keys: WinternitzPublicKey[],
    opts: TxOptions & TransactionKeyOptions = {}
  ): Promise<TransactionReceipt> {
    return this.keyManagementWrite(
      kind,
      keys,
      "addKeys",
      opts
    );
  }

  /// Replace the entire `kind` keyset with `keys`. Backend:
  /// `refreshKeys(bytes payload)`. Refreshing the Transaction keyset is
  /// forbidden at the contract level — this method throws
  /// `RefreshTransactionForbiddenError` synchronously when `kind` is
  /// Transaction so callers don't burn a key on a guaranteed-revert call.
  async refreshKeys(
    kind: KeyType,
    keys: WinternitzPublicKey[],
    opts: TxOptions & TransactionKeyOptions = {}
  ): Promise<TransactionReceipt> {
    if (kind === KeyType.Transaction) {
      throw new RefreshTransactionForbiddenError();
    }
    return this.keyManagementWrite(
      kind,
      keys,
      "refreshKeys",
      opts
    );
  }

  private async keyManagementWrite(
    kind: KeyType,
    keys: WinternitzPublicKey[],
    functionName: "addKeys" | "refreshKeys",
    opts: TxOptions & TransactionKeyOptions
  ): Promise<TransactionReceipt> {
    const { currentKey, nextKey, currentSeedBytes } =
      await this.pickTransactionKeyPair(opts);

    const codecKeys: CodecAddress[] = keys.map((k) => ({
      publicSeed: toHex(k.publicSeed),
      publicKeyHash: toHex(k.publicKeyHash),
    }));
    const digest = keysetDigest(
      kind,
      this.walletAddress,
      BigInt(this.chainId),
      currentKey.publicSeed,
      currentKey.publicKeyHash,
      nextKey.publicSeed,
      nextKey.publicKeyHash,
      codecKeysHash(codecKeys)
    );
    const pqSig = this.signWith(currentSeedBytes, digest);
    const payload = encodeKeyManagement(kind, currentKey, nextKey, pqSig, codecKeys);
    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName,
      args: [payload],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
  }

  /// Replace the key at `(kind, index)` with `newKey`. Backend:
  /// `replaceKeyAt(bytes payload)`.
  async replaceKeyAt(
    kind: KeyType,
    index: bigint,
    newKey: WinternitzPublicKey,
    opts: TxOptions & TransactionKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const { currentKey, nextKey, currentSeedBytes } =
      await this.pickTransactionKeyPair(opts);
    const codecNewKey: CodecAddress = {
      publicSeed: toHex(newKey.publicSeed),
      publicKeyHash: toHex(newKey.publicKeyHash),
    };

    const digest = replaceKeyAtDigest(
      kind,
      this.walletAddress,
      BigInt(this.chainId),
      currentKey.publicSeed,
      currentKey.publicKeyHash,
      nextKey.publicSeed,
      nextKey.publicKeyHash,
      index,
      codecNewKey.publicSeed,
      codecNewKey.publicKeyHash
    );
    const pqSig = this.signWith(currentSeedBytes, digest);
    const payload = encodeReplaceKeyAt(
      kind,
      currentKey,
      nextKey,
      pqSig,
      index,
      codecNewKey
    );
    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "replaceKeyAt",
      args: [payload],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
  }

  /// PQ-authenticated `recoverWallet(bytes)`. The caller supplies a recovery
  /// key's public seed; the SDK recovers the keypair, generates a fresh
  /// replacement recovery key + a fresh transaction key (the new sole entry
  /// in the cleared transaction keyset), signs the digest, and submits.
  async recoverWallet(
    recoveryPublicSeed: Uint8Array,
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const recoveryKeyPair = this.quipSigner.recoverKeyPair(
      this.vaultId,
      recoveryPublicSeed
    );
    const newRecoveryKeyPair = this.quipSigner.generateKeyPair(this.vaultId);
    const newTransactionKeyPair = this.quipSigner.generateKeyPair(this.vaultId);

    const recoveryKey: CodecAddress = {
      publicSeed: toHex(recoveryKeyPair.publicKey.publicSeed),
      publicKeyHash: toHex(recoveryKeyPair.publicKey.publicKeyHash),
    };
    const newRecoveryKey: CodecAddress = {
      publicSeed: toHex(newRecoveryKeyPair.publicKey.publicSeed),
      publicKeyHash: toHex(newRecoveryKeyPair.publicKey.publicKeyHash),
    };
    const newTransactionKey: CodecAddress = {
      publicSeed: toHex(newTransactionKeyPair.publicKey.publicSeed),
      publicKeyHash: toHex(newTransactionKeyPair.publicKey.publicKeyHash),
    };

    const digest = recoverWalletDigest(
      this.walletAddress,
      BigInt(this.chainId),
      recoveryKey.publicSeed,
      recoveryKey.publicKeyHash,
      newRecoveryKey.publicSeed,
      newRecoveryKey.publicKeyHash,
      newTransactionKey.publicSeed,
      newTransactionKey.publicKeyHash
    );
    const pqSig = this.signWith(recoveryPublicSeed, digest);
    const payload = encodeRecoverWallet(
      recoveryKey,
      newRecoveryKey,
      newTransactionKey,
      pqSig
    );

    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "recoverWallet",
      args: [payload],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
  }
}
