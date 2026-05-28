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
  zeroHash,
} from "viem";

import { quipWalletAbi } from "./abi/QuipWallet.js";
import { quipPaymasterAbi } from "./abi/QuipPaymaster.js";
import { entryPointV07Abi } from "./abi/EntryPointV07.js";
import { QuipSigner } from "./signer.js";
import { withDecodedError } from "./internal/decodeError.js";
import { tryMulticall } from "./internal/multicall.js";
import {
  type TxOptions,
  type PreparedTx,
  type ContractCallParams,
  prepareTx,
} from "./gas.js";
import {
  DuplicateKeyError,
  EmptyKeysError,
  Erc1271ValidationResult,
  GasEstimationError,
  IncorrectRecoveryKeyAmountError,
  IncorrectTransactionKeyAmountError,
  PartialMulticallResultError,
  PaymasterValidationFailure,
  RefreshTransactionForbiddenError,
  UnknownKeyError,
  UserOpValidationFailure,
} from "./errors.js";
import { decodeContractError } from "./internal/decodeError.js";
import {
  type PackedUserOperation,
  type WinternitzAddress,
  type WinternitzElements,
  KeyType,
  TRANSACTION_KEY_INIT_AMOUNT,
  RECOVERY_KEY_AMOUNT,
  computeUserOpHash,
  decodePaymasterAndData,
  decodeUserOpSignature,
  encodeExecute,
  encodeKeyManagement,
  encodeOwnershipTransfer,
  encodeRecoveryUpgrade,
  encodeReplaceKeyAt,
  encodeSaveWallet,
  encodeUpgradeToAndCall,
  encodeUserOpSignature,
  encodeWithdrawDeposit,
  encodeRecoverWallet,
  erc4337ExecuteDigest,
  executeDigest,
  keysetDigest,
  keysHash as codecKeysHash,
  opdataHash as codecOpdataHash,
  ownershipTransferKeysHash,
  packAccountGasLimits,
  packGasFees,
  paymasterVerifierKeyUsedSlot,
  replaceKeyAtDigest,
  saveWalletDigest,
  saveWalletKeysHash,
  transferOwnershipDigest,
  upgradeDigest,
  upgradeRecoveryDigest,
  withdrawDepositDigest,
  recoverWalletDigest,
} from "./wotsCodec.js";
import { buildUserOp } from "./userOp.js";
import {
  DEFAULT_VERIFICATION_GAS_LIMIT,
  DEFAULT_CALL_GAS_LIMIT,
  DEFAULT_PRE_VERIFICATION_GAS,
} from "./constants.js";

/// Re-export the codec's canonical `WinternitzAddress` shape so consumers
/// reaching into `walletClient` for `WalletState`-shaped types keep working.
/// The codec is the single source of truth for this contract-shape type.
export type { WinternitzAddress } from "./wotsCodec.js";

/// Per-call overrides for how the SDK picks which transaction-keyset entry
/// to sign with. See `SDK_README.md` for the full operational contract
/// (every broadcast burns a key; concurrent ops require distinct keys).
///
/// Two paths:
///   - `signWithKey` (explicit) — sign with this exact key.
///   - Default — sign with `keyAt(Transaction, 0)` (the on-chain head).
///
/// Concurrent writes MUST pass distinct `signWithKey` values; the SDK has
/// no in-process key-selection logic beyond "head or what you told me".
/// If the head has been burned (in-session reuse, or a previously-broadcast
/// sig recorded against the injected burn set), the signer's `consume`
/// throws `KeyAlreadyBurnedError` and the caller must retry with an
/// explicit `signWithKey`.
export interface TransactionKeyOptions {
  /// Explicit override — sign with this exact key. Must be a member of
  /// the transaction keyset on chain; the SDK pre-checks via
  /// `isKey(Transaction, ...)` and throws `UnknownKeyError` synchronously
  /// before any WOTS+ work if the key has rotated out.
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

/// `KeyType` lives in `wotsCodec.ts` as the single source of truth (it
/// mirrors `WOTSPlusCodec.KeyType` directly). Re-exported here so callers
/// reaching into `walletClient` for `KeyType` keep working — the value is
/// the same enum object as `WotsCodec.KeyType`, so identity comparisons
/// across modules succeed.
export { KeyType } from "./wotsCodec.js";

/// Split a merged `TxOptions & TransactionKeyOptions` into the two distinct
/// option bags consumed by the write pipeline: `keyOpts` drives key
/// selection (`pickTransactionKeyPair`), `txOpts` drives gas/fee/nonce
/// resolution (`prepareTx`). Same input, two semantically distinct outputs.
function splitWriteOpts(
  opts: TxOptions & TransactionKeyOptions
): { keyOpts: TransactionKeyOptions; txOpts: TxOptions } {
  const { signWithKey, ...txOpts } = opts;
  const keyOpts: TransactionKeyOptions = {};
  if (signWithKey !== undefined) keyOpts.signWithKey = signWithKey;
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
/// `EntryPoint.handleOps`, plus the digests and key pair used for
/// inspection / replay checks / burn-store reconciliation. `currentKey`
/// is the now-burned signing key; `nextKey` is the freshly generated
/// successor that the wallet will rotate into on a successful run.
export interface BuildExecuteUserOpResult {
  userOp: PackedUserOperation;
  walletDigest: Hex;
  userOpHash: Hex;
  currentKey: WinternitzAddress;
  nextKey: WinternitzAddress;
  executeFee: bigint;
}

/// Output of `prepareExecuteUserOp` — the unsigned UserOp + the
/// transaction keys the wallet will sign with. Pass through a paymaster
/// (if sponsoring) and then to `signExecuteUserOp` to finalize.
export interface PreparedExecuteUserOp {
  userOp: PackedUserOperation; // signature="0x", paymasterAndData="0x"
  currentKey: WinternitzAddress;
  nextKey: WinternitzAddress;
  entryPoint: Address;
  executeFee: bigint;
}

/// Unpacked view of the ERC-4337 `validationData` value
/// (`[validAfter(48) | validUntil(48) | authorizer(160)]`).
/// `authorizer == 0` means the signature is valid, `authorizer == 1` is
/// the canonical SIG_VALIDATION_FAILED sentinel, anything else is a
/// future-style aggregator/authorizer address.
export interface ValidationData {
  /// Raw packed value as returned by `validateUserOp` /
  /// `validatePaymasterUserOp`.
  raw: bigint;
  /// Low 160 bits — 0 = accept, 1 = sig invalid, else authorizer address.
  authorizer: bigint;
  /// 48-bit `validUntil` window (0 = no upper bound).
  validUntil: number;
  /// 48-bit `validAfter` window (0 = no lower bound).
  validAfter: number;
}

function unpackValidationData(raw: bigint): ValidationData {
  const authorizer = raw & ((1n << 160n) - 1n);
  const validUntil = Number((raw >> 160n) & ((1n << 48n) - 1n));
  const validAfter = Number((raw >> 208n) & ((1n << 48n) - 1n));
  return { raw, authorizer, validUntil, validAfter };
}

/// Result of `simulateUserOp` — covers both wallet- and paymaster-side
/// validation prediction.
///
/// `walletValidation`:
///   - `'ok'`: the wallet will return 0 (sig verifies, no early-exit hit)
///   - `UserOpValidationFailure` enum value: the specific reason the
///     wallet will emit `UserOpValidationRejected` for
///
/// `paymasterValidation`:
///   - `'no-paymaster'`: `paymasterAndData` is empty — unsponsored UserOp
///   - `'ok'`: paymaster will accept (sig verifies, no early-exit hit)
///   - `PaymasterValidationFailure` enum value: the specific reason
///     the paymaster will emit `PaymasterValidationRejected` for. Note:
///     `NextVerifierKeyInUse` and `InvalidSignature` are both surfaced
///     as `InvalidSignature` when the SDK can't statically distinguish
///     them — the contract storage layout for `verifierKeyUsed` is
///     consulted to catch the `NextVerifierKeyInUse` case when possible.
///
/// `walletValidationData` / `paymasterValidationData`: the unpacked
/// validation-data word the contract returned, when the SDK actually
/// invoked `eth_call` against `validateUserOp` / `validatePaymasterUserOp`
/// to reach the verdict. `null` when the SDK short-circuited via a
/// pre-check (e.g. `StaleCurrentKey` was detected client-side without
/// reaching the contract). For sponsored UserOps the paymaster value
/// carries `validUntil` / `validAfter` and lets callers see the validity
/// window even when the verdict is `'ok'`.
///
/// `keysBurnedIfRevert`: if the UserOp is broadcast and execution
/// reverts, will the corresponding key be rotated on chain (i.e. is the
/// key consumed regardless of execution outcome)?
///   - `wallet`: `true` when wallet validation would pass — the
///     EntryPoint commits the rotation before invoking execution.
///   - `paymaster`: `true` when paymaster validation would pass — same
///     rotation-during-validation rule.
/// `false` for either when its validation would fail (EntryPoint rejects
/// before state mutation). The SDK marks both keys burned in their
/// respective signers regardless, since the WOTS+ signatures were
/// revealed publicly — see `SDK_README.md`.
export interface SimulateUserOpResult {
  walletValidation: "ok" | UserOpValidationFailure;
  walletValidationData: ValidationData | null;
  paymasterValidation: "ok" | "no-paymaster" | PaymasterValidationFailure;
  paymasterValidationData: ValidationData | null;
  keysBurnedIfRevert: { wallet: boolean; paymaster: boolean };
}

/// Descriptor passed to `prepareSignedWrite`. Captures the variation
/// between the codec-payload writes (executeWithPayload, withdrawDeposit,
/// addKeys/refreshKeys, replaceKeyAt) so the orchestration code lives in
/// one place.
interface SignedWriteSpec {
  buildDigest: (currentKey: WinternitzAddress, nextKey: WinternitzAddress) => Hex;
  buildPayload: (
    currentKey: WinternitzAddress,
    nextKey: WinternitzAddress,
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
  private vaultId: Hex;
  private chainId: number;

  constructor(
    quipSigner: QuipSigner,
    vaultId: Hex,
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
  /// `transferOwnership(bytes)`. Stored at a fixed slot on chain and
  /// rotates on use.
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

  /// Returns true if `key` has ever been installed in this wallet — in any
  /// keyset (transaction / recovery / verification) or either single-key
  /// slot (`disasterRecoveryKey`, `ownershipKey`). Mirrors the contract's
  /// monotonic `isKeySpent` burn index: once true, stays true even after
  /// the key has been rotated out of its live slot.
  ///
  /// Use this rather than `isKey(kind, key)` for pre-flight checks before
  /// sending a userOp whose `nextKey` is subject to the contract's
  /// `_enforceUnspentKey` guard — `isKey` covers only currently-live
  /// membership and will miss historically-burned keys.
  async isKeySpent(key: WinternitzAddress): Promise<boolean> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "isKeySpent",
        args: [key],
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

  /// Read every key in `kind`'s set, ordered by storage index. Single
  /// `eth_call` against the contract's `getKeyset(kind)` view.
  async getKeyset(kind: KeyType): Promise<WinternitzAddress[]> {
    const keys = await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "getKeyset",
        args: [kind],
      })
    );
    return [...(keys as readonly WinternitzAddress[])];
  }

  async getWalletState(): Promise<WalletState> {
    const calls = [
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "owner" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "quipFactory" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "entryPoint" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "getExecuteFee" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "getDeposit" as const },
      { address: this.walletAddress, abi: quipWalletAbi, functionName: "getAllKeys" as const },
    ];

    const results = await tryMulticall(this.publicClient, calls, {
      chainId: this.chainId,
    });

    const labels = [
      "owner",
      "quipFactory",
      "entryPoint",
      "getExecuteFee",
      "getDeposit",
      "getAllKeys",
    ] as const;

    const failures: { label: string; error: Error }[] = [];
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.status === "failure") {
        failures.push({ label: labels[i], error: r.error });
      }
    }
    if (failures.length > 0) {
      throw new PartialMulticallResultError(failures);
    }

    const owner = (results[0] as { status: "success"; result: Address }).result;
    const factory = (results[1] as { status: "success"; result: Address }).result;
    const entryPoint = (results[2] as { status: "success"; result: Address }).result;
    const executeFee = (results[3] as { status: "success"; result: bigint }).result;
    const deposit = (results[4] as { status: "success"; result: bigint }).result;
    const allKeys = (
      results[5] as {
        status: "success";
        result: {
          disasterRecoveryKey: WinternitzAddress;
          ownershipKey: WinternitzAddress;
          transactionKeys: readonly WinternitzAddress[];
          recoveryKeys: readonly WinternitzAddress[];
          verificationKeys: readonly WinternitzAddress[];
        };
      }
    ).result;

    const transactionKeys = [...allKeys.transactionKeys];
    const recoveryKeys = [...allKeys.recoveryKeys];
    const verificationKeys = [...allKeys.verificationKeys];

    return {
      owner,
      factory,
      entryPoint,
      executeFee,
      deposit,
      disasterRecoveryKey: allKeys.disasterRecoveryKey,
      ownershipKey: allKeys.ownershipKey,
      keyCounts: {
        transaction: BigInt(transactionKeys.length),
        recovery: BigInt(recoveryKeys.length),
        verification: BigInt(verificationKeys.length),
      },
      transactionKeys,
      recoveryKeys,
      verificationKeys,
    };
  }

  /// Funnel for every payload-based write. Each write method builds its
  /// codec payload + contract call params, then delegates to this helper for
  /// simulation, gas estimation, sending, and receipt waiting. The signing
  /// key was already burned via the injected `ConsumeKeyFn` at the moment
  /// `QuipSigner.sign(...)` produced the signature.
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
  private signWith(currentSeed: Hex, digest: Hex): WinternitzElements {
    return {
      elements: this.quipSigner.sign(digest, this.vaultId, currentSeed),
    };
  }

  /// Pick a transaction key to sign with according to `keyOpts`:
  ///   - `signWithKey` (explicit override) wins. Pre-flight `isKey(Transaction,
  ///     signWithKey)` verifies the key still lives in the keyset on chain,
  ///     throwing `UnknownKeyError` synchronously if it has rotated out.
  ///     This runs *before* `quipSigner.sign(...)` so a stale `signWithKey`
  ///     does NOT burn the key on a guaranteed-revert call.
  ///   - default: `keyAt(Transaction, 0)` (the on-chain head). Always a
  ///     live key by construction.
  ///
  /// In both paths, `quipSigner.sign(...)` invokes the injected
  /// `ConsumeKeyFn` first thing. If the chosen key has already been burned
  /// (in-session reuse, or a previously-broadcast sig recorded by the
  /// caller in their burn store), `consume` throws `KeyAlreadyBurnedError`
  /// before any WOTS+ work runs.
  ///
  /// Generates a fresh next key in all cases.
  private async pickTransactionKeyPair(
    keyOpts?: TransactionKeyOptions
  ): Promise<{ currentKey: WinternitzAddress; nextKey: WinternitzAddress }> {
    let current: WinternitzAddress;
    if (keyOpts?.signWithKey) {
      const live = await this.isKey(KeyType.Transaction, keyOpts.signWithKey);
      if (!live) throw new UnknownKeyError();
      current = keyOpts.signWithKey;
    } else {
      current = await this.getHeadTransactionKey();
    }
    const next = this.quipSigner.generateKeyPair(this.vaultId);
    return { currentKey: current, nextKey: next.publicKey };
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
    const { currentKey, nextKey } = await this.pickTransactionKeyPair(keyOpts);
    const digest = spec.buildDigest(currentKey, nextKey);
    const pqSig = this.signWith(currentKey.publicSeed, digest);
    const payload = spec.buildPayload(currentKey, nextKey, pqSig);
    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: spec.functionName,
      args: [payload],
      account: this.account,
      ...(spec.totalValue > 0n && { value: spec.totalValue }),
    };
    return this.executeWrite(contractCall, spec.totalValue, txOpts);
  }

  /// Pre-flight validation for batch key-management writes. Synchronous
  /// throws on empty array and within-batch duplicates so the SDK doesn't
  /// burn a transaction key on a guaranteed-revert call. The contract is
  /// authoritative for cross-keyset uniqueness (`KeyInUseError`) and
  /// existing-set duplicates (`DuplicateKeyError`).
  private validateKeyBatch(keys: WinternitzAddress[]): void {
    if (keys.length === 0) throw new EmptyKeysError();
    const seen = new Set<string>();
    for (const k of keys) {
      const id = `${k.publicSeed}:${k.publicKeyHash}`;
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
    const { currentKey, nextKey } = await this.pickTransactionKeyPair(opts);
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
    const pqSig = this.signWith(currentKey.publicSeed, digest);
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
    keys: WinternitzAddress[],
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
    keys: WinternitzAddress[],
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
    keys: WinternitzAddress[],
    functionName: "addKeys" | "refreshKeys",
    opts: TxOptions & TransactionKeyOptions
  ): Promise<TransactionReceipt> {
    const keysetHashHex = codecKeysHash(keys);
    const { keyOpts, txOpts } = splitWriteOpts(opts);
    return this.prepareSignedWrite(
      {
        buildDigest: (currentKey, nextKey) =>
          keysetDigest(
            kind,
            functionName === "refreshKeys",
            this.walletAddress,
            BigInt(this.chainId),
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            keysetHashHex
          ),
        buildPayload: (currentKey, nextKey, pqSig) =>
          encodeKeyManagement(kind, currentKey, nextKey, pqSig, keys),
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
    newKey: WinternitzAddress,
    opts: TxOptions & TransactionKeyOptions = {}
  ): Promise<TransactionReceipt> {
    this.validateKeyBatch([newKey]);
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
            newKey.publicSeed,
            newKey.publicKeyHash
          ),
        buildPayload: (currentKey, nextKey, pqSig) =>
          encodeReplaceKeyAt(
            kind,
            currentKey,
            nextKey,
            pqSig,
            index,
            newKey
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
    recoveryPublicSeed: Hex,
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const recoveryKey = this.quipSigner.recoverKeyPair(
      this.vaultId,
      recoveryPublicSeed
    ).publicKey;
    const newRecoveryKey = this.quipSigner.generateKeyPair(this.vaultId).publicKey;
    const newTransactionKey = this.quipSigner.generateKeyPair(this.vaultId).publicKey;

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

  /// PQ-authenticated `saveWallet(bytes)` — last-resort rescue authorized by
  /// the wallet's `disasterRecoveryKey`. Clears the transaction + recovery
  /// keysets and reinstalls fresh batches, while rotating the
  /// disaster-recovery key itself. The verification keyset and classical
  /// `owner()` are left intact.
  ///
  /// All replacement key material is generated by the SDK: a new disaster
  /// recovery key, 5 new transaction keys, and 10 new recovery keys, each
  /// derived under this signer/vault. The signing disaster-recovery key
  /// is marked burned in `QuipSigner` once the signature is produced.
  async saveWallet(
    disasterRecoveryPublicSeed: Hex,
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const currentDisaster = this.quipSigner.recoverKeyPair(
      this.vaultId,
      disasterRecoveryPublicSeed
    ).publicKey;
    const newDisaster = this.quipSigner.generateKeyPair(this.vaultId).publicKey;
    const newTransactionKeys: WinternitzAddress[] = Array.from(
      { length: TRANSACTION_KEY_INIT_AMOUNT },
      () => this.quipSigner.generateKeyPair(this.vaultId).publicKey
    );
    const newRecoveryKeys: WinternitzAddress[] = Array.from(
      { length: RECOVERY_KEY_AMOUNT },
      () => this.quipSigner.generateKeyPair(this.vaultId).publicKey
    );

    const keysHashHex = saveWalletKeysHash(
      newTransactionKeys,
      newRecoveryKeys
    );
    const digest = saveWalletDigest(
      this.walletAddress,
      BigInt(this.chainId),
      currentDisaster.publicSeed,
      currentDisaster.publicKeyHash,
      newDisaster.publicSeed,
      newDisaster.publicKeyHash,
      keysHashHex
    );
    const pqSig = this.signWith(disasterRecoveryPublicSeed, digest);
    const payload = encodeSaveWallet(
      currentDisaster,
      newDisaster,
      pqSig,
      newTransactionKeys,
      newRecoveryKeys
    );

    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "saveWallet",
      args: [payload],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
  }

  /// PQ-authenticated `transferOwnership(bytes)` — rotates the classical
  /// `owner()` to `newOwner` AND fully re-initializes the wallet's PQ state
  /// (ownership key, disaster-recovery key, transaction keyset, recovery
  /// keyset). The new owner controls all the supplied key material; the
  /// caller must source those keys from the recipient (they live in the
  /// recipient's vault, not the current signer's).
  ///
  /// Signing key: the wallet's current `ownershipKey`, derived from
  /// `ownershipPublicSeed`. Marked burned after the signature is produced.
  async transferOwnership(
    ownershipPublicSeed: Hex,
    params: {
      newOwner: Address;
      newOwnershipKey: WinternitzAddress;
      newDisasterRecoveryKey: WinternitzAddress;
      newTransactionKeys: WinternitzAddress[]; // exactly 5
      newRecoveryKeys: WinternitzAddress[]; // exactly 10
    },
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    if (params.newTransactionKeys.length !== TRANSACTION_KEY_INIT_AMOUNT) {
      throw new IncorrectTransactionKeyAmountError();
    }
    if (params.newRecoveryKeys.length !== RECOVERY_KEY_AMOUNT) {
      throw new IncorrectRecoveryKeyAmountError();
    }

    const currentOwnership = this.quipSigner.recoverKeyPair(
      this.vaultId,
      ownershipPublicSeed
    ).publicKey;
    const keysHashHex = ownershipTransferKeysHash(
      params.newDisasterRecoveryKey,
      params.newTransactionKeys,
      params.newRecoveryKeys
    );
    const digest = transferOwnershipDigest(
      this.walletAddress,
      BigInt(this.chainId),
      currentOwnership.publicSeed,
      currentOwnership.publicKeyHash,
      params.newOwnershipKey.publicSeed,
      params.newOwnershipKey.publicKeyHash,
      params.newOwner,
      keysHashHex
    );
    const pqSig = this.signWith(ownershipPublicSeed, digest);
    const payload = encodeOwnershipTransfer(
      currentOwnership,
      params.newOwnershipKey,
      pqSig,
      params.newOwner,
      params.newDisasterRecoveryKey,
      params.newTransactionKeys,
      params.newRecoveryKeys
    );

    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "transferOwnership",
      args: [payload],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
  }

  /// PQ-authenticated `upgradeToAndCall(address, bytes)`. Two signatures
  /// required:
  ///   1. `pqSig` from the wallet's current transaction key (the SDK signs
  ///      this internally — same key-allocation rules as `executeWithPayload`).
  ///   2. `verifySig` from a verifier key embedded in the new
  ///      implementation's attestation. The caller supplies `verifier` +
  ///      `verifySig` — these come from the impl deployer, not the wallet
  ///      owner.
  ///
  /// Set `migrationPayload` to a 1088-byte init payload to trigger
  /// `migrate(...)` against the new implementation. Leave undefined (or pass
  /// `"0x"`) for a no-migration upgrade; the SDK zero-fills the trailing 1088
  /// bytes the contract requires for layout symmetry.
  async upgradeWallet(
    newImplementation: Address,
    verifier: WinternitzAddress,
    verifySig: WinternitzElements,
    options: {
      migrationPayload?: Hex;
    } = {},
    opts: TxOptions & TransactionKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const { keyOpts, txOpts } = splitWriteOpts(opts);
    const { currentKey, nextKey } = await this.pickTransactionKeyPair(keyOpts);
    const digest = upgradeDigest(
      this.walletAddress,
      BigInt(this.chainId),
      newImplementation,
      currentKey.publicSeed,
      currentKey.publicKeyHash,
      nextKey.publicSeed,
      nextKey.publicKeyHash
    );
    const pqSig = this.signWith(currentKey.publicSeed, digest);
    const shouldMigrate =
      options.migrationPayload !== undefined && options.migrationPayload !== "0x";
    const payload = encodeUpgradeToAndCall(
      currentKey,
      nextKey,
      pqSig,
      verifier,
      verifySig,
      shouldMigrate,
      options.migrationPayload ?? "0x"
    );

    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "upgradeToAndCall",
      args: [newImplementation, payload],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, txOpts);
  }

  /// PQ-authenticated `recoveryUpgrade(address, bytes)` — emergency upgrade
  /// authorized by a recovery key + the new implementation's verifier
  /// attestation. No state migration is performed (recovery upgrades are for
  /// breaking-glass cases; consumers who need to migrate state can call
  /// `upgradeWallet` after recovery if needed).
  ///
  /// The recovery key used to sign rotates in-place: `newRecoveryKey`
  /// replaces `currentRecoveryKey` so the recovery-keyset size stays stable.
  /// `newRecoveryKey` defaults to a fresh keypair generated under this
  /// signer/vault.
  async recoveryUpgrade(
    recoveryPublicSeed: Hex,
    newImplementation: Address,
    verifier: WinternitzAddress,
    verifySig: WinternitzElements,
    options: { newRecoveryKey?: WinternitzAddress } = {},
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const currentRecoveryKey = this.quipSigner.recoverKeyPair(
      this.vaultId,
      recoveryPublicSeed
    ).publicKey;
    const newRecoveryKey =
      options.newRecoveryKey ??
      this.quipSigner.generateKeyPair(this.vaultId).publicKey;

    const digest = upgradeRecoveryDigest(
      this.walletAddress,
      BigInt(this.chainId),
      newImplementation,
      currentRecoveryKey.publicSeed,
      currentRecoveryKey.publicKeyHash,
      newRecoveryKey.publicSeed,
      newRecoveryKey.publicKeyHash
    );
    const pqSig = this.signWith(recoveryPublicSeed, digest);
    const payload = encodeRecoveryUpgrade(
      currentRecoveryKey,
      newRecoveryKey,
      pqSig,
      verifier,
      verifySig
    );

    const contractCall: ContractCallParams = {
      address: this.walletAddress,
      abi: quipWalletAbi,
      functionName: "recoveryUpgrade",
      args: [newImplementation, payload],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
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
    const prepared = await this.prepareExecuteUserOp(target, value, data, opts);
    return this.signExecuteUserOp(prepared);
  }

  /// Build the unsigned UserOp shell for an `execute(target, value, data)`
  /// call. Resolves nonce, fees, and gas limits; encodes callData; picks
  /// the wallet's current/next transaction keys. Does NOT sign — for the
  /// sponsored flow, the caller hands the result to a paymaster which
  /// fills `paymasterAndData`, then calls `signExecuteUserOp` to finalize.
  ///
  /// For the unsponsored flow, `buildExecuteUserOp` (which composes
  /// prepare + sign) is simpler.
  async prepareExecuteUserOp(
    target: Address,
    value: bigint,
    data: Hex,
    opts: BuildExecuteUserOpOptions & TransactionKeyOptions = {}
  ): Promise<PreparedExecuteUserOp> {
    const callData = encodeFunctionData({
      abi: quipWalletAbi,
      functionName: "execute",
      args: [target, value, data],
    });
    return this._prepareUserOpFromCallData(callData, opts, async (entryPoint) =>
      this.estimateExecuteCallGas(entryPoint, target, value, data)
    );
  }

  /// Build an unsigned `executeBatch(Call[])` UserOp. The wallet runs each
  /// inner call sequentially via Solady's ERC-4337 base; the WOTS+ rotation
  /// commits during validation so the whole batch shares a single key burn.
  async prepareExecuteBatchUserOp(
    calls: ReadonlyArray<{ target: Address; value: bigint; data: Hex }>,
    opts: BuildExecuteUserOpOptions & TransactionKeyOptions = {}
  ): Promise<PreparedExecuteUserOp> {
    const callData = encodeFunctionData({
      abi: quipWalletAbi,
      functionName: "executeBatch",
      args: [calls.map((c) => ({ target: c.target, value: c.value, data: c.data }))],
    });
    return this._prepareUserOpFromCallData(callData, opts);
  }

  /// Build an unsigned `delegateExecute(delegate, data)` UserOp. The wallet
  /// delegatecalls into `delegate`; guarded slots (owner, impl, factory,
  /// disaster/ownership keys) are snapshotted before and asserted unchanged
  /// after — tampering reverts with `GuardedSlotTampered`.
  async prepareDelegateExecuteUserOp(
    delegate: Address,
    data: Hex,
    opts: BuildExecuteUserOpOptions & TransactionKeyOptions = {}
  ): Promise<PreparedExecuteUserOp> {
    const callData = encodeFunctionData({
      abi: quipWalletAbi,
      functionName: "delegateExecute",
      args: [delegate, data],
    });
    return this._prepareUserOpFromCallData(callData, opts);
  }

  /// Build an unsigned `storageStore(slot, value)` UserOp. Writes `value`
  /// at `slot` via `SSTORE`; the wallet's `storageStoreGuard` rejects
  /// guarded slots (owner / ERC-1967 impl / factory / disaster + ownership
  /// key slots) with `GuardedSlotWriteDenied`.
  async prepareStorageStoreUserOp(
    slot: Hex,
    value: Hex,
    opts: BuildExecuteUserOpOptions & TransactionKeyOptions = {}
  ): Promise<PreparedExecuteUserOp> {
    const callData = encodeFunctionData({
      abi: quipWalletAbi,
      functionName: "storageStore",
      args: [slot, value],
    });
    return this._prepareUserOpFromCallData(callData, opts);
  }

  /// Sugar: prepare + sign `executeBatch`.
  async buildExecuteBatchUserOp(
    calls: ReadonlyArray<{ target: Address; value: bigint; data: Hex }>,
    opts: BuildExecuteUserOpOptions & TransactionKeyOptions = {}
  ): Promise<BuildExecuteUserOpResult> {
    const prepared = await this.prepareExecuteBatchUserOp(calls, opts);
    return this.signExecuteUserOp(prepared);
  }

  /// Sugar: prepare + sign `delegateExecute`.
  async buildDelegateExecuteUserOp(
    delegate: Address,
    data: Hex,
    opts: BuildExecuteUserOpOptions & TransactionKeyOptions = {}
  ): Promise<BuildExecuteUserOpResult> {
    const prepared = await this.prepareDelegateExecuteUserOp(delegate, data, opts);
    return this.signExecuteUserOp(prepared);
  }

  /// Sugar: prepare + sign `storageStore`.
  async buildStorageStoreUserOp(
    slot: Hex,
    value: Hex,
    opts: BuildExecuteUserOpOptions & TransactionKeyOptions = {}
  ): Promise<BuildExecuteUserOpResult> {
    const prepared = await this.prepareStorageStoreUserOp(slot, value, opts);
    return this.signExecuteUserOp(prepared);
  }

  /// Shared pipeline behind every `prepare*UserOp` method: picks the
  /// transaction keypair, resolves nonce / fees / gas limits, packs the
  /// unsigned UserOp. `gasEstimator`, when supplied, is invoked once with
  /// the resolved entryPoint and is responsible for both pre-flighting
  /// the inner call AND returning a callGasLimit estimate.
  private async _prepareUserOpFromCallData(
    callData: Hex,
    opts: BuildExecuteUserOpOptions & TransactionKeyOptions,
    gasEstimator?: (entryPoint: Address) => Promise<bigint>
  ): Promise<PreparedExecuteUserOp> {
    const { keyOpts } = splitWriteOpts(
      opts as TxOptions & TransactionKeyOptions
    );
    const entryPoint = opts.entryPoint ?? (await this.getEntryPoint());
    const fee = await this.getExecuteFee();

    // Pick the current/next keypair. Does NOT burn — signing does that
    // later inside `signExecuteUserOp`.
    const { currentKey, nextKey } = await this.pickTransactionKeyPair(keyOpts);

    // Resolve nonce.
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

    // Resolve fees. Caller overrides win; otherwise pull from chain.
    let maxFeePerGas = opts.maxFeePerGas;
    let maxPriorityFeePerGas = opts.maxPriorityFeePerGas;
    if (maxFeePerGas === undefined || maxPriorityFeePerGas === undefined) {
      const fees = await this.publicClient.estimateFeesPerGas();
      maxFeePerGas = maxFeePerGas ?? fees.maxFeePerGas;
      maxPriorityFeePerGas = maxPriorityFeePerGas ?? fees.maxPriorityFeePerGas;
    }

    // Resolve gas limits — explicit overrides, else estimate, else defaults.
    let callGasLimit = opts.callGasLimit;
    const verificationGasLimit =
      opts.verificationGasLimit ?? DEFAULT_VERIFICATION_GAS_LIMIT;
    const preVerificationGas =
      opts.preVerificationGas ?? DEFAULT_PRE_VERIFICATION_GAS;

    if (callGasLimit === undefined && !opts.skipGasEstimation) {
      if (gasEstimator) {
        callGasLimit = await gasEstimator(entryPoint);
      } else {
        callGasLimit = await this.estimateInnerCallGasFromCallData(
          entryPoint,
          callData
        );
      }
    }
    if (callGasLimit === undefined) {
      callGasLimit = DEFAULT_CALL_GAS_LIMIT;
    }

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

    return {
      userOp: unsigned,
      currentKey,
      nextKey,
      entryPoint,
      executeFee: fee,
    };
  }

  /// Generic `eth_estimateGas` from the EntryPoint against pre-encoded
  /// `callData`. Same revert-decoding pattern as `estimateExecuteCallGas`
  /// so reverts surface as typed `QuipError`s; non-revert failures
  /// become `GasEstimationError`.
  private async estimateInnerCallGasFromCallData(
    entryPoint: Address,
    callData: Hex
  ): Promise<bigint> {
    try {
      return await this.publicClient.estimateGas({
        account: entryPoint,
        to: this.walletAddress,
        data: callData,
      });
    } catch (err) {
      const decoded = decodeContractError(err);
      if (decoded) throw decoded;
      const message = err instanceof Error ? err.message : String(err);
      throw new GasEstimationError(message, { cause: err });
    }
  }

  /// Finalize an unsigned UserOp by signing the wallet's portion. Takes
  /// the result of `prepareExecuteUserOp` (possibly after a paymaster has
  /// substituted `paymasterAndData` via `sponsorUserOp`). Computes the
  /// final `userOpHash` (now reflecting the paymaster bytes), builds the
  /// wallet digest, signs with WOTS+, and embeds the signature into
  /// `userOp.signature`.
  ///
  /// The WOTS+ signature burns the wallet's current transaction key at
  /// `QuipSigner.sign(...)` time — once this method returns, that key is
  /// dead.
  async signExecuteUserOp(
    prepared: PreparedExecuteUserOp
  ): Promise<BuildExecuteUserOpResult> {
    const { userOp, currentKey, nextKey, entryPoint, executeFee } = prepared;
    const userOpHash = computeUserOpHash(
      userOp,
      entryPoint,
      BigInt(this.chainId)
    );
    const walletDigest = erc4337ExecuteDigest(
      this.walletAddress,
      BigInt(this.chainId),
      currentKey.publicSeed,
      currentKey.publicKeyHash,
      nextKey.publicSeed,
      nextKey.publicKeyHash,
      userOpHash,
      executeFee
    );
    const pqSig = this.signWith(currentKey.publicSeed, walletDigest);
    const signature = encodeUserOpSignature(currentKey, nextKey, pqSig);
    return {
      userOp: { ...userOp, signature },
      walletDigest,
      userOpHash,
      currentKey,
      nextKey,
      executeFee,
    };
  }

  /// Predict the wallet- and paymaster-side validation outcome of `userOp`
  /// without broadcasting.
  ///
  /// Strategy: local pre-checks first (cheap reads), then state-override
  /// `eth_call`s to `wallet.validateUserOp(...)` and (if a paymaster is
  /// attached) `paymaster.validatePaymasterUserOp(...)`, both with
  /// `from = entryPoint`. Pre-checks enumerate the deterministic
  /// rejection paths; `eth_call` catches the remaining
  /// `InvalidSignature` cases.
  async simulateUserOp(
    userOp: PackedUserOperation,
    opts: { entryPoint?: Address } = {}
  ): Promise<SimulateUserOpResult> {
    const entryPoint = opts.entryPoint ?? (await this.getEntryPoint());

    // --- Wallet side ---
    const walletPart = await this.simulateWalletValidation(
      userOp,
      entryPoint
    );

    // --- Paymaster side ---
    const paymasterPart = await this.simulatePaymasterValidation(
      userOp,
      entryPoint
    );

    return {
      walletValidation: walletPart.result,
      walletValidationData: walletPart.validationData,
      paymasterValidation: paymasterPart.result,
      paymasterValidationData: paymasterPart.validationData,
      keysBurnedIfRevert: {
        wallet: walletPart.wouldRotate,
        paymaster: paymasterPart.wouldRotate,
      },
    };
  }

  private async simulateWalletValidation(
    userOp: PackedUserOperation,
    entryPoint: Address
  ): Promise<{
    result: "ok" | UserOpValidationFailure;
    wouldRotate: boolean;
    validationData: ValidationData | null;
  }> {
    // Decode currentKey / nextKey out of userOp.signature. The codec lays
    // them out as [currentKey(64) | nextKey(64) | pqSig(2144)]. The decoder
    // throws on any short / malformed signature; treat that as InvalidSignature.
    let currentKey: WinternitzAddress;
    let nextKey: WinternitzAddress;
    try {
      const decoded = decodeUserOpSignature(userOp.signature);
      currentKey = decoded.currentKey;
      nextKey = decoded.nextKey;
    } catch {
      return {
        result: UserOpValidationFailure.InvalidSignature,
        wouldRotate: false,
        validationData: null,
      };
    }

    // 1. ZeroNextKey
    if (
      nextKey.publicSeed === zeroHash ||
      nextKey.publicKeyHash === zeroHash
    ) {
      return {
        result: UserOpValidationFailure.ZeroNextKey,
        wouldRotate: false,
        validationData: null,
      };
    }

    // 2. StaleCurrentKey — currentKey must be in the transaction keyset.
    const currentIsActive = await this.isKey(KeyType.Transaction, currentKey);
    if (!currentIsActive) {
      return {
        result: UserOpValidationFailure.StaleCurrentKey,
        wouldRotate: false,
        validationData: null,
      };
    }

    // 3. NextKeyAlreadyInUse — nextKey must not have been previously
    //    installed in any slot. Mirrors the contract's monotonic
    //    `_enforceUnspentKey` check via the `isKeySpent` burn index.
    const inUse = await this.isKeySpent(nextKey);
    if (inUse) {
      return {
        result: UserOpValidationFailure.NextKeyAlreadyInUse,
        wouldRotate: false,
        validationData: null,
      };
    }

    // 4. InvalidSignature — final gate via eth_call.
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
        result: UserOpValidationFailure.InvalidSignature,
        wouldRotate: false,
        validationData: null,
      };
    }
    const validationRaw = decodeFunctionResult({
      abi: quipWalletAbi,
      functionName: "validateUserOp",
      data: callResult.data,
    }) as bigint;
    const validationData = unpackValidationData(validationRaw);
    if (validationData.authorizer === 0n) {
      return { result: "ok", wouldRotate: true, validationData };
    }
    return {
      result: UserOpValidationFailure.InvalidSignature,
      wouldRotate: false,
      validationData,
    };
  }

  private async simulatePaymasterValidation(
    userOp: PackedUserOperation,
    entryPoint: Address
  ): Promise<{
    result: "ok" | "no-paymaster" | PaymasterValidationFailure;
    wouldRotate: boolean;
    validationData: ValidationData | null;
  }> {
    // No paymaster attached → not sponsored.
    if (userOp.paymasterAndData === "0x" || userOp.paymasterAndData.length <= 2) {
      return { result: "no-paymaster", wouldRotate: false, validationData: null };
    }

    // MalformedPayload: must be exactly 2272 bytes. The decoder throws on
    // length mismatch (the paymaster also rejects any other length on chain).
    let paymaster: Address;
    let nextVerifier: WinternitzAddress;
    try {
      const decoded = decodePaymasterAndData(userOp.paymasterAndData);
      paymaster = decoded.paymaster;
      nextVerifier = decoded.nextVerifier;
    } catch {
      return {
        result: PaymasterValidationFailure.MalformedPayload,
        wouldRotate: false,
        validationData: null,
      };
    }

    // ZeroNextVerifier
    if (
      nextVerifier.publicSeed === zeroHash ||
      nextVerifier.publicKeyHash === zeroHash
    ) {
      return {
        result: PaymasterValidationFailure.ZeroNextVerifier,
        wouldRotate: false,
        validationData: null,
      };
    }

    // NoVerifierRegistered — check the paymaster's on-chain verifier for
    // the sender.
    let currentVerifier: WinternitzAddress;
    try {
      currentVerifier = await withDecodedError(
        this.publicClient.readContract({
          address: paymaster,
          abi: quipPaymasterAbi,
          functionName: "getPqVerifier",
          args: [userOp.sender],
        })
      );
    } catch {
      // If the read fails (paymaster address has no code, RPC error),
      // treat as no-verifier; the on-chain validation would also fail
      // hard on this path.
      return {
        result: PaymasterValidationFailure.NoVerifierRegistered,
        wouldRotate: false,
        validationData: null,
      };
    }
    if (
      currentVerifier.publicSeed === zeroHash ||
      currentVerifier.publicKeyHash === zeroHash
    ) {
      return {
        result: PaymasterValidationFailure.NoVerifierRegistered,
        wouldRotate: false,
        validationData: null,
      };
    }

    // NextEqualsCurrent
    if (
      currentVerifier.publicSeed === nextVerifier.publicSeed &&
      currentVerifier.publicKeyHash === nextVerifier.publicKeyHash
    ) {
      return {
        result: PaymasterValidationFailure.NextEqualsCurrent,
        wouldRotate: false,
        validationData: null,
      };
    }

    // NextVerifierKeyInUse — read the paymaster's monotonic
    // `verifierKeyUsed[hash]` mapping directly. The codec derives the
    // storage slot per the ERC-7201 layout in `QuipPaymasterStorage.sol`.
    const mappingSlot = paymasterVerifierKeyUsedSlot(nextVerifier);
    try {
      const storageValue = await this.publicClient.getStorageAt({
        address: paymaster,
        slot: mappingSlot,
      });
      if (storageValue !== undefined && BigInt(storageValue) !== 0n) {
        return {
          result: PaymasterValidationFailure.NextVerifierKeyInUse,
          wouldRotate: false,
          validationData: null,
        };
      }
    } catch {
      // Best-effort; fall through to the signature check.
    }

    // Final gate: InvalidSignature via eth_call.
    const userOpHash = computeUserOpHash(
      userOp,
      entryPoint,
      BigInt(this.chainId)
    );
    const validateData = encodeFunctionData({
      abi: quipPaymasterAbi,
      functionName: "validatePaymasterUserOp",
      args: [userOp, userOpHash, 0n],
    });
    let callResult: { data?: Hex };
    try {
      callResult = await this.publicClient.call({
        account: entryPoint,
        to: paymaster,
        data: validateData,
      });
    } catch {
      return {
        result: PaymasterValidationFailure.InvalidSignature,
        wouldRotate: false,
        validationData: null,
      };
    }
    if (!callResult.data) {
      return {
        result: PaymasterValidationFailure.InvalidSignature,
        wouldRotate: false,
        validationData: null,
      };
    }
    const decoded = decodeFunctionResult({
      abi: quipPaymasterAbi,
      functionName: "validatePaymasterUserOp",
      data: callResult.data,
    }) as readonly [Hex, bigint];
    const validationData = unpackValidationData(decoded[1]);
    if (validationData.authorizer !== 0n) {
      return {
        result: PaymasterValidationFailure.InvalidSignature,
        wouldRotate: false,
        validationData,
      };
    }
    return { result: "ok", wouldRotate: true, validationData };
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

  /// Read the wallet's current implementation version — the index of the
  /// ERC-1967 impl's codehash in the factory's vetted set, or
  /// `type(uint256).max` if the deployed code is no longer recognized.
  async version(): Promise<bigint> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "version",
      })
    );
  }

  /// Off-chain diagnostic for ERC-1271 `isValidSignature` failures.
  /// Returns the specific failure branch (`BadSignatureLength`,
  /// `InvalidEcdsaSignature`, `UnknownVerifier`, `InvalidPqSignature`)
  /// or `Ok` on success — the production `isValidSignature` collapses
  /// all four failures into the single ERC-1271 sentinel.
  async debugIsValidSignature(
    hash: Hex,
    signature: Hex
  ): Promise<Erc1271ValidationResult> {
    const raw = await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "debugIsValidSignature",
        args: [hash, signature],
      })
    );
    return Number(raw) as Erc1271ValidationResult;
  }

  /// Read the expiry timestamp for an in-flight ownership handover
  /// initiated for `pendingOwner`. Zero when no handover is active for
  /// that address. Solady's `Ownable` model is time-bound per
  /// requesting address — there is no single "the pending owner" slot
  /// on the wallet; each candidate's pending state is keyed by their
  /// own address.
  async ownershipHandoverExpiresAt(pendingOwner: Address): Promise<bigint> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: quipWalletAbi,
        functionName: "ownershipHandoverExpiresAt",
        args: [pendingOwner],
      })
    );
  }

  /// Gas estimate for `wallet.execute(target, value, data)` from the
  /// EntryPoint. Pre-flights the inner call: a revert here throws *before*
  /// `signExecuteUserOp` is called, so no transaction key is burned on a
  /// guaranteed-revert userOp.
  ///
  /// Failure modes:
  ///   - Contract revert with a recognized selector → decoded `QuipError`
  ///     subclass (e.g. `InvalidSignatureError`) or `UnknownContractError`
  ///     carrying the raw selector + bytes for non-Quip ABIs.
  ///   - Bare `revert()` / OOG / network failure → `GasEstimationError`
  ///     with the viem error attached as `cause`.
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
    } catch (err) {
      const decoded = decodeContractError(err);
      if (decoded) throw decoded;
      const message = err instanceof Error ? err.message : String(err);
      throw new GasEstimationError(message, { cause: err });
    }
  }

}
