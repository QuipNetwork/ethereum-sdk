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
  decodeFunctionResult,
  encodeFunctionData,
  hexToBytes,
  toHex,
  zeroHash,
} from "viem";

import { quipWalletAbi } from "./abi/QuipWallet.js";
import { entryPointV07Abi } from "./abi/EntryPointV07.js";
import { QuipSigner, type WinternitzPublicKey } from "./signer.js";
import { withDecodedError } from "./internal/decodeError.js";
import { tryMulticall, type TryMulticallResult } from "./internal/multicall.js";
import {
  type TxOptions,
  type PreparedTx,
  type ContractCallParams,
  prepareTx,
} from "./gas.js";
import {
  DuplicateKeyError,
  EmptyKeysError,
  NoAvailableTransactionKeysError,
  PartialMulticallResultError,
  RefreshTransactionForbiddenError,
  UserOpValidationFailure,
} from "./errors.js";
import {
  type WinternitzAddress as CodecAddress,
  type WinternitzElements,
  encodeExecute,
  encodeKeyManagement,
  encodeReplaceKeyAt,
  encodeWithdrawDeposit,
  encodeRecoverWallet,
  encodeUserOpSignature,
  executeDigest,
  keysetDigest,
  keysHash as codecKeysHash,
  opdataHash as codecOpdataHash,
  replaceKeyAtDigest,
  withdrawDepositDigest,
  recoverWalletDigest,
} from "./wotsCodec.js";
import {
  type PackedUserOperation,
  buildUserOp,
  computeUserOpHash,
  packAccountGasLimits,
  packGasFees,
  walletUserOpDigest,
  DEFAULT_VERIFICATION_GAS_LIMIT,
  DEFAULT_CALL_GAS_LIMIT,
  DEFAULT_PRE_VERIFICATION_GAS,
} from "./userOp.js";

/// 32-byte WOTS+ key tuple as returned by the contract's `keyAt` and stored
/// in the SDK's read-aggregator outputs.
export interface WinternitzAddress {
  publicSeed: Hex;
  publicKeyHash: Hex;
}

/// Per-call overrides for how the SDK picks which transaction-keyset entry
/// to sign with. See `SDK_README.md` for the full operational contract
/// (every broadcast burns a key; concurrent ops require distinct keys).
///
/// Precedence: `signWithKey` (explicit) wins. Otherwise `keyAllocationStrategy`
/// chooses between the head and a walked-keyset search.
export interface TransactionKeyOptions {
  /// Explicit override — sign with this exact key. Must be a member of
  /// the transaction keyset; the contract reverts `UnknownKey` otherwise.
  /// Useful for HSM/split-custody flows where the caller owns key
  /// selection.
  signWithKey?: WinternitzAddress;

  /// 'head'           — default; signs with `keyAt(Transaction, 0)`. Safe
  ///                    for single-threaded write flows. Unsafe under
  ///                    concurrent submission (multiple in-flight ops
  ///                    would all pick the same head and double-use the
  ///                    key).
  /// 'next-available' — walks the keyset and signs with the first key not
  ///                    in `QuipSigner`'s burned set. Use this whenever
  ///                    multiple writes may be in flight simultaneously
  ///                    or when retrying after a revert. Throws
  ///                    `NoAvailableTransactionKeysError` if the keyset
  ///                    is exhausted.
  keyAllocationStrategy?: "head" | "next-available";
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

/// Split a merged `TxOptions & TransactionKeyOptions` into the two distinct
/// option bags consumed by the write pipeline: `keyOpts` drives key
/// selection (`pickTransactionKeyPair`), `txOpts` drives gas/fee/nonce
/// resolution (`prepareTx`). Same input, two semantically distinct outputs.
function splitWriteOpts(
  opts: TxOptions & TransactionKeyOptions
): { keyOpts: TransactionKeyOptions; txOpts: TxOptions } {
  const { signWithKey, keyAllocationStrategy, ...txOpts } = opts;
  const keyOpts: TransactionKeyOptions = {};
  if (signWithKey !== undefined) keyOpts.signWithKey = signWithKey;
  if (keyAllocationStrategy !== undefined)
    keyOpts.keyAllocationStrategy = keyAllocationStrategy;
  return { keyOpts, txOpts };
}

/// Per-call options for `buildExecuteUserOp`. All gas/fee fields are
/// optional — when omitted, the SDK falls back to state-override gas
/// estimation against the configured EntryPoint (then to conservative
/// defaults if estimation fails). Nonce defaults to `EntryPoint.getNonce(sender, nonceKey)`.
export interface BuildExecuteUserOpOptions {
  /// Explicit override for `verificationGasLimit`. Skips state-override
  /// estimation when present.
  verificationGasLimit?: bigint;
  /// Explicit override for `callGasLimit`. Skips state-override estimation
  /// when present.
  callGasLimit?: bigint;
  /// Explicit override for `preVerificationGas`. Defaults to
  /// `DEFAULT_PRE_VERIFICATION_GAS` — preVerificationGas is mostly L1
  /// calldata cost, so a static value is reasonable for L1; per-chain
  /// override needed for L2s with non-trivial calldata pricing.
  preVerificationGas?: bigint;
  /// Explicit `maxFeePerGas` override. If omitted, derived from the public
  /// client's fee estimator.
  maxFeePerGas?: bigint;
  /// Explicit `maxPriorityFeePerGas` override. If omitted, derived from
  /// the public client's fee estimator.
  maxPriorityFeePerGas?: bigint;
  /// Explicit `nonce` override. If omitted, fetched from
  /// `EntryPoint.getNonce(sender, nonceKey)`.
  nonce?: bigint;
  /// `nonceKey` (uint192) for parallel-nonce flows. Default 0.
  nonceKey?: bigint;
  /// Disable state-override gas estimation. Falls back to `DEFAULT_*`
  /// constants. Useful on chains that don't support state overrides or
  /// when the caller already has reliable estimates.
  skipGasEstimation?: boolean;
  /// Override the EntryPoint address used for `userOpHash` computation
  /// and nonce lookup. Defaults to the wallet's on-chain `entryPoint()`.
  entryPoint?: Address;
}

/// Result of `buildExecuteUserOp` — the fully signed UserOp ready for
/// `EntryPoint.handleOps`, plus the digests for inspection / replay
/// checks.
export interface BuildExecuteUserOpResult {
  userOp: PackedUserOperation;
  walletDigest: Hex;
  userOpHash: Hex;
}

/// Result of `simulateUserOp` — wallet-side validation prediction. Phase
/// 5b extends this to cover paymaster validation.
///
/// `walletValidation`:
///   - `'ok'`: the wallet will return 0 (sig verifies, no early-exit hit)
///   - `UserOpValidationFailure` enum value: the specific reason the
///     wallet will emit `UserOpValidationRejected` for
///
/// `keysBurnedIfRevert`: if the UserOp is broadcast and execution
/// reverts, will the wallet-side transaction key be rotated on chain
/// (i.e. is the key consumed regardless of execution outcome)? `true`
/// when validation would pass — the EntryPoint commits the rotation
/// before invoking execution, so a reverted inner call still burns the
/// key on chain. `false` when validation would fail — the EntryPoint
/// rejects the UserOp before any state mutation. (The SDK marks the key
/// burned in `QuipSigner` regardless, since the WOTS+ signature was
/// revealed publicly — see `SDK_README.md`.)
export interface SimulateUserOpResult {
  walletValidation: "ok" | UserOpValidationFailure;
  keysBurnedIfRevert: boolean;
}

/// Descriptor passed to `prepareSignedWrite`. Captures the variation
/// between the codec-payload writes (executeWithPayload, withdrawDeposit,
/// addKeys/refreshKeys, replaceKeyAt) so the orchestration code lives in
/// one place.
interface SignedWriteSpec {
  buildDigest: (currentKey: CodecAddress, nextKey: CodecAddress) => Hex;
  buildPayload: (
    currentKey: CodecAddress,
    nextKey: CodecAddress,
    pqSig: WinternitzElements
  ) => Hex;
  functionName: "execute" | "withdrawDepositTo" | "addKeys" | "refreshKeys" | "replaceKeyAt";
  totalValue: bigint;
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

  /// Wallet's ETH balance held with the ERC-4337 EntryPoint (used to pay
  /// for sponsored UserOps when the wallet covers its own gas).
  async getDeposit(): Promise<bigint> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "getDeposit",
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
  /// chosen key as `signWithKey` on the relevant write method, or use
  /// `keyAllocationStrategy: 'next-available'`.
  async getHeadTransactionKey(): Promise<WinternitzAddress> {
    return this.keyAt(KeyType.Transaction, 0n);
  }

  /// Read every key in `kind`'s set, ordered by index. Two RPC round-trips
  /// at most: one for `keyCount`, one for the multicalled `keyAt` reads
  /// (or sequential fallback on chains without Multicall3). Throws
  /// `PartialMulticallResultError` if any individual `keyAt` fails.
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

    const failures: { label: string; error: Error }[] = [];
    const keys: WinternitzAddress[] = [];
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.status === "success") {
        keys.push(r.result as WinternitzAddress);
      } else {
        failures.push({ label: `keyAt(${KeyType[kind]}, ${i})`, error: r.error });
      }
    }
    if (failures.length > 0) {
      throw new PartialMulticallResultError(failures);
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

    const labels = [
      "owner",
      "quipFactory",
      "entryPoint",
      "getExecuteFee",
      "getDeposit",
      "getDisasterRecoveryKey",
      "getOwnershipKey",
      "keyCount(Transaction)",
      "keyCount(Recovery)",
      "keyCount(Verification)",
    ] as const;

    const scalarFailures: { label: string; error: Error }[] = [];
    for (let i = 0; i < scalars.length; i++) {
      const r = scalars[i];
      if (r.status === "failure") {
        scalarFailures.push({ label: labels[i], error: r.error });
      }
    }
    if (scalarFailures.length > 0) {
      throw new PartialMulticallResultError(scalarFailures);
    }

    const owner = (scalars[0] as { status: "success"; result: Address }).result;
    const factory = (scalars[1] as { status: "success"; result: Address }).result;
    const entryPoint = (scalars[2] as { status: "success"; result: Address }).result;
    const executeFee = (scalars[3] as { status: "success"; result: bigint }).result;
    const deposit = (scalars[4] as { status: "success"; result: bigint }).result;
    const disasterRecoveryKey = (scalars[5] as { status: "success"; result: WinternitzAddress }).result;
    const ownershipKey = (scalars[6] as { status: "success"; result: WinternitzAddress }).result;
    const txCount = (scalars[7] as { status: "success"; result: bigint }).result;
    const rcCount = (scalars[8] as { status: "success"; result: bigint }).result;
    const vfCount = (scalars[9] as { status: "success"; result: bigint }).result;

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
        ? ([] as TryMulticallResult<unknown>[])
        : (await tryMulticall(this.publicClient, allKeyCalls, {
            chainId: this.chainId,
            ...(opts?.forceSequential && { forceSequential: true }),
          }) as TryMulticallResult<unknown>[]);

    const txEnd = Number(txCount);
    const rcEnd = txEnd + Number(rcCount);
    const vfEnd = rcEnd + Number(vfCount);

    const labelOfIndex = (i: number): string => {
      if (i < txEnd) return `keyAt(Transaction, ${i})`;
      if (i < rcEnd) return `keyAt(Recovery, ${i - txEnd})`;
      return `keyAt(Verification, ${i - rcEnd})`;
    };

    const keyFailures: { label: string; error: Error }[] = [];
    for (let i = 0; i < keyResults.length; i++) {
      const r = keyResults[i];
      if (r.status === "failure") {
        keyFailures.push({ label: labelOfIndex(i), error: r.error });
      }
    }
    if (keyFailures.length > 0) {
      throw new PartialMulticallResultError(keyFailures);
    }

    const okKeys = keyResults.map(
      (r) => (r as { status: "success"; result: WinternitzAddress }).result
    );

    const transactionKeys = okKeys.slice(0, txEnd);
    const recoveryKeys = okKeys.slice(txEnd, rcEnd);
    const verificationKeys = okKeys.slice(rcEnd, vfEnd);

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
  /// simulation, gas estimation, sending, receipt waiting, and the
  /// post-broadcast burn of the signing key.
  private async executeWrite(
    contractCall: ContractCallParams,
    totalValue: bigint,
    opts: TxOptions,
    signingKeyPublicSeed: Hex
  ): Promise<TransactionReceipt> {
    const prepared = await prepareTx({
      publicClient: this.publicClient,
      contractParams: contractCall,
      totalValue,
      opts,
    });
    return this.submit(contractCall, prepared, signingKeyPublicSeed);
  }

  private async submit(
    contractCall: ContractCallParams,
    prepared: PreparedTx,
    signingKeyPublicSeed: Hex
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

    // Idempotent safety-net. `QuipSigner.sign(...)` already burned this
    // key when the signature was produced (above, in `signWith`). We
    // re-mark here so the burn is recorded even if the signer is ever
    // swapped for an implementation that doesn't auto-burn (e.g. a
    // future HSM-backed `PqSigner`).
    this.quipSigner.markBurned(signingKeyPublicSeed);

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

  /// Pick a transaction key to sign with according to `keyOpts`:
  ///   - `signWithKey` (explicit override) wins
  ///   - `keyAllocationStrategy: 'next-available'` walks the keyset and
  ///     returns the first unburned key (throws `NoAvailableTransactionKeysError`
  ///     when exhausted)
  ///   - default ('head'): `keyAt(Transaction, 0)`
  /// Generates a fresh next key in all cases.
  private async pickTransactionKeyPair(
    keyOpts?: TransactionKeyOptions
  ): Promise<{
    currentKey: CodecAddress;
    nextKey: CodecAddress;
    currentSeedBytes: Uint8Array;
  }> {
    let current: WinternitzAddress;
    if (keyOpts?.signWithKey) {
      current = keyOpts.signWithKey;
    } else if (keyOpts?.keyAllocationStrategy === "next-available") {
      const keyset = await this.getKeyset(KeyType.Transaction);
      const unburned = keyset.find(
        (k) => !this.quipSigner.isBurned(k.publicSeed)
      );
      if (!unburned) {
        throw new NoAvailableTransactionKeysError(keyset.length);
      }
      current = unburned;
    } else {
      current = await this.getHeadTransactionKey();
    }
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

  /// Run the standard pick → digest → sign → encode → submit pipeline for
  /// any codec-payload write that signs with a transaction key. Centralizes
  /// the orchestration so individual write methods only describe their
  /// digest builder, payload encoder, function name, and value.
  private async prepareSignedWrite(
    spec: SignedWriteSpec,
    keyOpts: TransactionKeyOptions,
    txOpts: TxOptions
  ): Promise<TransactionReceipt> {
    const { currentKey, nextKey, currentSeedBytes } =
      await this.pickTransactionKeyPair(keyOpts);
    const digest = spec.buildDigest(currentKey, nextKey);
    const pqSig = this.signWith(currentSeedBytes, digest);
    const payload = spec.buildPayload(currentKey, nextKey, pqSig);
    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: spec.functionName,
      args: [payload],
      account: this.account,
      ...(spec.totalValue > 0n && { value: spec.totalValue }),
    };
    return this.executeWrite(
      contractCall,
      spec.totalValue,
      txOpts,
      currentKey.publicSeed
    );
  }

  /// Pre-flight validation for batch key-management writes. Synchronous
  /// throws on empty array and within-batch duplicates so the SDK doesn't
  /// burn a transaction key on a guaranteed-revert call. The contract is
  /// authoritative for cross-keyset uniqueness (`KeyInUseError`) and
  /// existing-set duplicates (`DuplicateKeyError`).
  private validateKeyBatch(keys: WinternitzPublicKey[]): void {
    if (keys.length === 0) throw new EmptyKeysError();
    const seen = new Set<string>();
    for (const k of keys) {
      const id = `${toHex(k.publicSeed)}:${toHex(k.publicKeyHash)}`;
      if (seen.has(id)) throw new DuplicateKeyError();
      seen.add(id);
    }
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
    const fee = await this.getExecuteFee();
    const totalValue = fee + value;
    const { keyOpts, txOpts } = splitWriteOpts(opts);
    return this.prepareSignedWrite(
      {
        buildDigest: (currentKey, nextKey) =>
          executeDigest(
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
          ),
        buildPayload: (currentKey, nextKey, pqSig) =>
          encodeExecute(currentKey, nextKey, pqSig, target, value, data),
        functionName: "execute",
        totalValue,
      },
      keyOpts,
      txOpts
    );
  }

  /// Pre-flight version: return the prepared tx (gas + fees) without sending.
  /// Does NOT burn the signing key — no broadcast occurs.
  async estimateExecute(
    target: Address,
    value: bigint,
    data: Hex,
    opts: TxOptions & TransactionKeyOptions = {}
  ): Promise<PreparedTx> {
    const fee = await this.getExecuteFee();
    const totalValue = fee + value;
    const { currentKey, nextKey, currentSeedBytes } =
      await this.pickTransactionKeyPair(opts);
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
    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "execute",
      args: [payload],
      value: totalValue,
      account: this.account,
    };
    return prepareTx({
      publicClient: this.publicClient,
      contractParams: contractCall,
      totalValue,
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
    const { keyOpts, txOpts } = splitWriteOpts(opts);
    return this.prepareSignedWrite(
      {
        buildDigest: (currentKey, nextKey) =>
          withdrawDepositDigest(
            this.walletAddress,
            BigInt(this.chainId),
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            to,
            amount
          ),
        buildPayload: (currentKey, nextKey, pqSig) =>
          encodeWithdrawDeposit(currentKey, nextKey, pqSig, to, amount),
        functionName: "withdrawDepositTo",
        totalValue: 0n,
      },
      keyOpts,
      txOpts
    );
  }

  /// Add `keys` to the `kind` keyset. Backend: `addKeys(bytes payload)`.
  /// Synchronous pre-flight rejects empty batches and within-batch
  /// duplicates without consuming a transaction key.
  async addKeys(
    kind: KeyType,
    keys: WinternitzPublicKey[],
    opts: TxOptions & TransactionKeyOptions = {}
  ): Promise<TransactionReceipt> {
    this.validateKeyBatch(keys);
    return this.keyManagementWrite(kind, keys, "addKeys", opts);
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
    this.validateKeyBatch(keys);
    return this.keyManagementWrite(kind, keys, "refreshKeys", opts);
  }

  private async keyManagementWrite(
    kind: KeyType,
    keys: WinternitzPublicKey[],
    functionName: "addKeys" | "refreshKeys",
    opts: TxOptions & TransactionKeyOptions
  ): Promise<TransactionReceipt> {
    const codecKeys: CodecAddress[] = keys.map((k) => ({
      publicSeed: toHex(k.publicSeed),
      publicKeyHash: toHex(k.publicKeyHash),
    }));
    const keysetHashHex = codecKeysHash(codecKeys);
    const { keyOpts, txOpts } = splitWriteOpts(opts);
    return this.prepareSignedWrite(
      {
        buildDigest: (currentKey, nextKey) =>
          keysetDigest(
            kind,
            this.walletAddress,
            BigInt(this.chainId),
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            keysetHashHex
          ),
        buildPayload: (currentKey, nextKey, pqSig) =>
          encodeKeyManagement(kind, currentKey, nextKey, pqSig, codecKeys),
        functionName,
        totalValue: 0n,
      },
      keyOpts,
      txOpts
    );
  }

  /// Replace the key at `(kind, index)` with `newKey`. Backend:
  /// `replaceKeyAt(bytes payload)`. Synchronous pre-flight rejects a
  /// zero-equivalent batch via `validateKeyBatch([newKey])`.
  async replaceKeyAt(
    kind: KeyType,
    index: bigint,
    newKey: WinternitzPublicKey,
    opts: TxOptions & TransactionKeyOptions = {}
  ): Promise<TransactionReceipt> {
    this.validateKeyBatch([newKey]);
    const codecNewKey: CodecAddress = {
      publicSeed: toHex(newKey.publicSeed),
      publicKeyHash: toHex(newKey.publicKeyHash),
    };
    const { keyOpts, txOpts } = splitWriteOpts(opts);
    return this.prepareSignedWrite(
      {
        buildDigest: (currentKey, nextKey) =>
          replaceKeyAtDigest(
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
          ),
        buildPayload: (currentKey, nextKey, pqSig) =>
          encodeReplaceKeyAt(
            kind,
            currentKey,
            nextKey,
            pqSig,
            index,
            codecNewKey
          ),
        functionName: "replaceKeyAt",
        totalValue: 0n,
      },
      keyOpts,
      txOpts
    );
  }

  /// PQ-authenticated `recoverWallet(bytes)`. The caller supplies a recovery
  /// key's public seed; the SDK recovers the keypair, generates a fresh
  /// replacement recovery key + a fresh transaction key (the new sole entry
  /// in the cleared transaction keyset), signs the digest, and submits.
  /// The recovery key used to sign is marked burned in `QuipSigner` after
  /// broadcast — recovery keys are also one-time-use.
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
    return this.executeWrite(contractCall, 0n, opts, recoveryKey.publicSeed);
  }

  /// Build a fully wallet-signed `PackedUserOperation` for an `execute(target,
  /// value, data)` call routed through the ERC-4337 EntryPoint. Returns the
  /// UserOp with `signature` already populated and `paymasterAndData = "0x"`
  /// (no sponsorship — Phase 5b layers paymaster signing on top of this).
  ///
  /// Gas estimation: when `verificationGasLimit` / `callGasLimit` are not
  /// supplied, the SDK estimates `callGasLimit` via state-override `eth_call`
  /// against `wallet.execute(target, value, data)` with `from = entryPoint`.
  /// `verificationGasLimit` defaults to `DEFAULT_VERIFICATION_GAS_LIMIT`
  /// (the WOTS+ verify cost is roughly fixed and well-bounded). Estimation
  /// failures fall back to the `DEFAULT_*` constants — explicit overrides
  /// always win.
  ///
  /// Nonce: defaults to `EntryPoint.getNonce(sender, nonceKey ?? 0)`.
  ///
  /// Burn semantics: the signing key is marked burned the moment
  /// `QuipSigner.sign(...)` produces the WOTS+ signature inside this
  /// method — well before any broadcast. A subsequent `buildExecuteUserOp`
  /// (or any other sign call) targeting the same key throws
  /// `KeyAlreadyBurnedError`. If the caller chooses not to submit the
  /// returned UserOp, the key is still dead — that's the correct WOTS+
  /// semantic, because the signature exists and can leak.
  async buildExecuteUserOp(
    target: Address,
    value: bigint,
    data: Hex,
    opts: BuildExecuteUserOpOptions & TransactionKeyOptions = {}
  ): Promise<BuildExecuteUserOpResult> {
    const { keyOpts } = splitWriteOpts(
      opts as TxOptions & TransactionKeyOptions
    );
    const entryPoint =
      opts.entryPoint ?? (await this.getEntryPoint());
    const fee = await this.getExecuteFee();

    // 1. Pick the current/next keypair (same policy as direct writes).
    const { currentKey, nextKey } = await this.pickTransactionKeyPair(keyOpts);

    // 2. Encode the inner call. The EntryPoint-side `execute(target, value, data)`
    //    is the 3-arg overload at QuipWallet.sol:195 (onlyEntryPoint).
    const callData = encodeFunctionData({
      abi: quipWalletAbi,
      functionName: "execute",
      args: [target, value, data],
    });

    // 3. Resolve nonce.
    const nonce =
      opts.nonce ??
      (await withDecodedError(
        this.publicClient.readContract({
          address: entryPoint,
          abi: entryPointV07Abi,
          functionName: "getNonce",
          args: [this.walletAddress, opts.nonceKey ?? 0n],
        })
      ));

    // 4. Resolve fees. Caller overrides win; otherwise pull from chain.
    let maxFeePerGas = opts.maxFeePerGas;
    let maxPriorityFeePerGas = opts.maxPriorityFeePerGas;
    if (maxFeePerGas === undefined || maxPriorityFeePerGas === undefined) {
      const fees = await this.publicClient.estimateFeesPerGas();
      maxFeePerGas = maxFeePerGas ?? fees.maxFeePerGas;
      maxPriorityFeePerGas = maxPriorityFeePerGas ?? fees.maxPriorityFeePerGas;
    }

    // 5. Resolve gas limits — explicit overrides, else estimate, else defaults.
    let callGasLimit = opts.callGasLimit;
    const verificationGasLimit =
      opts.verificationGasLimit ?? DEFAULT_VERIFICATION_GAS_LIMIT;
    const preVerificationGas =
      opts.preVerificationGas ?? DEFAULT_PRE_VERIFICATION_GAS;

    if (callGasLimit === undefined && !opts.skipGasEstimation) {
      callGasLimit = await this.estimateExecuteCallGas(
        entryPoint,
        target,
        value,
        data
      );
    }
    if (callGasLimit === undefined) {
      callGasLimit = DEFAULT_CALL_GAS_LIMIT;
    }

    // 6. Build the unsigned UserOp.
    const unsigned = buildUserOp({
      sender: this.walletAddress,
      nonce,
      callData,
      verificationGasLimit,
      callGasLimit,
      preVerificationGas,
      maxFeePerGas,
      maxPriorityFeePerGas,
    });

    // 7. Compute userOpHash + walletDigest + sign.
    const userOpHash = computeUserOpHash(
      unsigned,
      entryPoint,
      BigInt(this.chainId)
    );
    const walletDigest = walletUserOpDigest({
      wallet: this.walletAddress,
      chainId: BigInt(this.chainId),
      currentKey,
      nextKey,
      userOpHash,
      executeFee: fee,
    });
    const pqSig = this.signWith(hexToBytes(currentKey.publicSeed), walletDigest);
    const signature = encodeUserOpSignature(currentKey, nextKey, pqSig);

    const userOp: PackedUserOperation = { ...unsigned, signature };
    return { userOp, walletDigest, userOpHash };
  }

  /// Idempotent safety-net for callers that build a UserOp and submit
  /// it elsewhere (bundler, custom handleOps path). `buildExecuteUserOp`
  /// already burns the key via `QuipSigner.sign(...)` at sign time, so
  /// this is a no-op in the normal flow. Kept for explicit intent and
  /// for HSM-backed signers that produce sigs outside `QuipSigner`.
  markUserOpKeyBurned(currentKey: WinternitzAddress | CodecAddress): void {
    this.quipSigner.markBurned(currentKey.publicSeed);
  }

  /// Predict the wallet's `validateUserOp` outcome without broadcasting.
  /// Phase 5a covers wallet-side only — paymaster simulation lands in 5b.
  ///
  /// Strategy: local pre-checks first (cheap reads), then a state-override
  /// `eth_call` to `wallet.validateUserOp(...)` with `from = entryPoint` to
  /// catch the remaining InvalidSignature case.
  async simulateUserOp(
    userOp: PackedUserOperation,
    opts: { entryPoint?: Address } = {}
  ): Promise<SimulateUserOpResult> {
    const entryPoint = opts.entryPoint ?? (await this.getEntryPoint());

    // Decode currentKey / nextKey out of userOp.signature. The codec lays
    // them out as [currentKey(64) | nextKey(64) | pqSig(2144)].
    if (userOp.signature.length < 2 + 2 * 64) {
      return { walletValidation: UserOpValidationFailure.InvalidSignature, keysBurnedIfRevert: false };
    }
    const sigBytes = hexToBytes(userOp.signature);
    if (sigBytes.length !== 64 + 64 + 67 * 32) {
      return { walletValidation: UserOpValidationFailure.InvalidSignature, keysBurnedIfRevert: false };
    }
    const currentKey: WinternitzAddress = {
      publicSeed: toHex(sigBytes.slice(0, 32)),
      publicKeyHash: toHex(sigBytes.slice(32, 64)),
    };
    const nextKey: WinternitzAddress = {
      publicSeed: toHex(sigBytes.slice(64, 96)),
      publicKeyHash: toHex(sigBytes.slice(96, 128)),
    };

    // 1. ZeroNextKey
    if (
      nextKey.publicSeed === zeroHash ||
      nextKey.publicKeyHash === zeroHash
    ) {
      return {
        walletValidation: UserOpValidationFailure.ZeroNextKey,
        keysBurnedIfRevert: false,
      };
    }

    // 2. StaleCurrentKey — currentKey must be in the transaction keyset.
    const currentIsActive = await this.isKey(KeyType.Transaction, currentKey);
    if (!currentIsActive) {
      return {
        walletValidation: UserOpValidationFailure.StaleCurrentKey,
        keysBurnedIfRevert: false,
      };
    }

    // 3. NextKeyAlreadyInUse — nextKey must not be present in any keyset
    //    (transaction / recovery / verification) or match a fixed key
    //    (disasterRecoveryKey / ownershipKey).
    const inUse = await this.isAnyKey(nextKey);
    if (inUse) {
      return {
        walletValidation: UserOpValidationFailure.NextKeyAlreadyInUse,
        keysBurnedIfRevert: false,
      };
    }

    // 4. InvalidSignature — final gate. eth_call to validateUserOp from
    //    entryPoint. The wallet's `_validateSignature` returns 0 on success,
    //    1 on signature failure. Set value=0 missingAccountFunds=0 so
    //    payPrefund doesn't try to forward ETH.
    const userOpHash = computeUserOpHash(
      userOp,
      entryPoint,
      BigInt(this.chainId)
    );
    const validateData = encodeFunctionData({
      abi: quipWalletAbi,
      functionName: "validateUserOp",
      args: [userOp, userOpHash, 0n],
    });
    const callResult = await this.publicClient.call({
      account: entryPoint,
      to: this.walletAddress,
      data: validateData,
    });
    if (!callResult.data) {
      return {
        walletValidation: UserOpValidationFailure.InvalidSignature,
        keysBurnedIfRevert: false,
      };
    }
    const validationData = decodeFunctionResult({
      abi: quipWalletAbi,
      functionName: "validateUserOp",
      data: callResult.data,
    });
    if (validationData === 0n) {
      // Validation would pass → key rotation committed during validation,
      // so an execution-time revert still burns the wallet-side key.
      return { walletValidation: "ok", keysBurnedIfRevert: true };
    }
    return {
      walletValidation: UserOpValidationFailure.InvalidSignature,
      keysBurnedIfRevert: false,
    };
  }

  /// Read the EntryPoint address from the wallet's `entryPoint()` view.
  async getEntryPoint(): Promise<Address> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "entryPoint",
      })
    );
  }

  /// State-override gas estimate for `wallet.execute(target, value, data)`
  /// from the EntryPoint. Returns `DEFAULT_CALL_GAS_LIMIT` on any estimation
  /// failure (chain doesn't support overrides, RPC rejected, target reverts).
  private async estimateExecuteCallGas(
    entryPoint: Address,
    target: Address,
    value: bigint,
    data: Hex
  ): Promise<bigint> {
    try {
      return await this.publicClient.estimateContractGas({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "execute",
        args: [target, value, data],
        account: entryPoint,
        value,
      } as unknown as Parameters<PublicClient["estimateContractGas"]>[0]);
    } catch {
      return DEFAULT_CALL_GAS_LIMIT;
    }
  }

  /// Returns true if `key` is present in any active keyset (transaction,
  /// recovery, verification) or matches the wallet's fixed disaster /
  /// ownership keys. Used by `simulateUserOp` to detect the
  /// `NextKeyAlreadyInUse` rejection path.
  private async isAnyKey(key: WinternitzAddress): Promise<boolean> {
    const [inTx, inRc, inVf, disaster, ownership] = await Promise.all([
      this.isKey(KeyType.Transaction, key),
      this.isKey(KeyType.Recovery, key),
      this.isKey(KeyType.Verification, key),
      this.getDisasterRecoveryKey(),
      this.getOwnershipKey(),
    ]);
    if (inTx || inRc || inVf) return true;
    if (
      disaster.publicSeed === key.publicSeed &&
      disaster.publicKeyHash === key.publicKeyHash
    )
      return true;
    if (
      ownership.publicSeed === key.publicSeed &&
      ownership.publicKeyHash === key.publicKeyHash
    )
      return true;
    return false;
  }
}
