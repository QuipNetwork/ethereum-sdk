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
  type Account,
  type Address,
  type Hex,
  type LocalAccount,
  type PublicClient,
  type TransactionReceipt,
  type WalletClient,
  encodeFunctionData,
  keccak256,
} from "viem";

import { assertProviderState, boundChain } from "../internal/providerState.js";
import { tryMulticall } from "../internal/multicall.js";
import { shrincsWalletAbi } from "./abi/ShrincsWallet.js";
import {
  ParameterSetId,
  parameterSetIdToEnum,
} from "./constants.js";
import {
  CommitmentMismatchError,
  Erc1271ValidationResult,
  StatefulBudgetExhaustedError,
  ZeroAddressOwnerError,
  ZeroErc1271CommitmentError,
} from "./errors.js";
import { prepareTx, type TxOptions } from "./gas.js";
import { withDecodedError } from "./internal/decodeError.js";
import {
  ACTION_ERC1271,
  ACTION_EXECUTE,
  ACTION_ROTATE_KEY,
  ACTION_SET_ERC1271_KEY,
  ACTION_TRANSFER_OWNERSHIP,
  ACTION_UPGRADE,
  ACTION_WITHDRAW,
  buildActionContext,
  buildRotationContext,
  buildStatefulRotationTarget,
  dataHash as keccakData,
  domainSeparator,
  encodeErc1271Signature,
  encodeUpgradeData,
  executePayloadHash,
  publicKeyToAbi,
  rotateKeyPayloadHash,
  setErc1271KeyPayloadHash,
  toRotationTarget,
  transferOwnershipPayloadHash,
  upgradePayloadHash,
  withdrawPayloadHash,
} from "./shrincsCodec.js";
import { type ShrincsKeyPair, type ShrincsSigner } from "./shrincsSigner.js";
import { type RotationTarget, type ShrincsPublicKey } from "./types.js";
import {
  type PackedUserOperation,
  buildUserOp,
  signWalletUserOp,
} from "./userOp.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;

export interface ShrincsWalletState {
  owner: Address;
  version: bigint;
  executeFee: bigint;
  shrincsPublicKeyCommitment: Hex;
  erc1271Commitment: Hex;
  parameterSetId: number;
  erc1271ParameterSetId: number;
  keyVersion: bigint;
  actionNonce: bigint;
  maxSignatures: number;
  statefulLeavesUsed: number;
  remainingStatefulSignatures: number;
}

export interface ShrincsTxKeyOptions {
  /// Override the leaf to sign at. Default: the lowest unused leaf read from the
  /// on-chain bitmap (the bitmap is authoritative — no in-memory burn set).
  leaf?: number;
}

/// A single call in an `executeBatch` userOp (mirrors the wallet's `Call`).
export interface ShrincsCall {
  target: Address;
  value?: bigint;
  data?: Hex;
}

/// ERC-4337 envelope fields shared by the userOp builders. Gas limits fall back
/// to conservative defaults; `nonce` and the fee fields are required because
/// they come from the EntryPoint / fee market, not a safe constant.
export interface UserOpEnvelope {
  nonce: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  verificationGasLimit?: bigint;
  callGasLimit?: bigint;
  preVerificationGas?: bigint;
  initCode?: Hex;
  paymasterAndData?: Hex;
}

export interface ShrincsWalletClientParams {
  walletAddress: Address;
  publicClient: PublicClient;
  walletClient: WalletClient;
  signer: ShrincsSigner;
  vaultId: Hex;
  chainId: number;
  account: Address;
}

/// Per-wallet read + write client for a `ShrincsWallet`. Mirrors the WOTS+
/// `WOTSPlusImplementationClient` with 1-1 feature parity, but tracks NO
/// in-memory leaf state: every stateful op re-reads the on-chain used-leaf
/// bitmap and signs at the lowest unused leaf.
export class ShrincsWalletClient {
  readonly walletAddress: Address;
  readonly chainId: number;
  readonly account: Address;
  readonly vaultId: Hex;

  private readonly publicClient: PublicClient;
  private readonly walletClient: WalletClient;
  private readonly signer: ShrincsSigner;

  constructor(params: ShrincsWalletClientParams) {
    this.walletAddress = params.walletAddress;
    this.publicClient = params.publicClient;
    this.walletClient = params.walletClient;
    this.signer = params.signer;
    this.vaultId = params.vaultId;
    this.chainId = params.chainId;
    this.account = params.account;
  }

  /*  ── reads ───────────────────────────────────────────────────────────  */

  /// Atomic snapshot of wallet state via Multicall3 (sequential fallback).
  async getWalletState(): Promise<ShrincsWalletState> {
    const fns = [
      "owner",
      "version",
      "getExecuteFee",
      "getShrincsPublicKeyCommitment",
      "getErc1271Commitment",
      "getParameterSetId",
      "getErc1271ParameterSetId",
      "keyVersion",
      "actionNonce",
      "maxSignatures",
      "statefulLeavesUsed",
      "remainingStatefulSignatures",
    ] as const;
    const results = await tryMulticall(
      this.publicClient,
      fns.map((functionName) => ({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName,
      }))
    );
    const get = (i: number) => {
      const r = results[i];
      if (!r || r.status !== "success") {
        throw new Error(`Failed to read ${fns[i]} from ${this.walletAddress}`);
      }
      return r.result as never;
    };
    return {
      owner: get(0),
      version: BigInt(get(1)),
      executeFee: BigInt(get(2)),
      shrincsPublicKeyCommitment: get(3),
      erc1271Commitment: get(4),
      parameterSetId: Number(get(5)),
      erc1271ParameterSetId: Number(get(6)),
      keyVersion: BigInt(get(7)),
      actionNonce: BigInt(get(8)),
      maxSignatures: Number(get(9)),
      statefulLeavesUsed: Number(get(10)),
      remainingStatefulSignatures: Number(get(11)),
    };
  }

  async isStatefulLeafUsed(leaf: number): Promise<boolean> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "isStatefulLeafUsed",
        args: [BigInt(leaf)],
      })
    ) as Promise<boolean>;
  }

  /// Lowest unused stateful leaf in `1..maxSignatures` for the current key
  /// epoch, found by scanning the on-chain bitmap via multicall. Throws
  /// `StatefulBudgetExhaustedError` if every leaf is consumed.
  async lowestUnusedLeaf(
    maxSignatures: number,
    statefulLeavesUsed: number
  ): Promise<number> {
    if (statefulLeavesUsed >= maxSignatures) {
      throw new StatefulBudgetExhaustedError(maxSignatures, statefulLeavesUsed);
    }
    const calls = [];
    for (let leaf = 1; leaf <= maxSignatures; leaf++) {
      calls.push({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "isStatefulLeafUsed" as const,
        args: [BigInt(leaf)] as const,
      });
    }
    const results = await tryMulticall(this.publicClient, calls);
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r && r.status === "success" && r.result === false) return i + 1;
    }
    throw new StatefulBudgetExhaustedError(maxSignatures, statefulLeavesUsed);
  }

  /// The QuipFactory that deployed this wallet (the remaining `IShrincsWallet`
  /// view not bundled into `getWalletState`).
  async quipFactory(): Promise<Address> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "quipFactory",
      })
    ) as Promise<Address>;
  }

  /// This wallet's ETH deposit held at the EntryPoint — what pays for its own
  /// userOps when they are not sponsored by a paymaster.
  async getDeposit(): Promise<bigint> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "getDeposit",
      })
    ) as Promise<bigint>;
  }

  /// ERC-1271: `true` iff `(hash, signature)` is accepted (i.e. the contract
  /// returns the `0x1626ba7e` magic value). `signature` is an
  /// `encodeErc1271Signature` blob.
  async isValidSignature(hash: Hex, signature: Hex): Promise<boolean> {
    const magic = (await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "isValidSignature",
        args: [hash, signature],
      })
    )) as Hex;
    return magic.toLowerCase() === "0x1626ba7e";
  }

  /// ERC-1271 diagnostic: the precise `Erc1271ValidationResult` reason instead of
  /// the magic-value collapse — use to tell *why* a signature was rejected.
  async debugIsValidSignature(
    hash: Hex,
    signature: Hex
  ): Promise<Erc1271ValidationResult> {
    const result = (await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "debugIsValidSignature",
        args: [hash, signature],
      })
    )) as number;
    return Number(result) as Erc1271ValidationResult;
  }

  /// The EIP-712 typed-data digest the ERC-1271 ECDSA half must sign. Read from
  /// chain so it always matches the deployed domain (name/version/verifyingContract).
  async quipSignedHashEcdsaTarget(hash: Hex): Promise<Hex> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "quipSignedHashEcdsaTarget",
        args: [hash],
      })
    ) as Promise<Hex>;
  }

  /// Pre-flight the `verifyUpgrade` reachability probe as a staticcall: resolves
  /// if `data` (an `encodeUpgradeData` blob) re-verifies against `newImplementation`,
  /// otherwise throws the decoded contract error. Run before `upgradeToAndCall`.
  async verifyUpgrade(newImplementation: Address, data: Hex): Promise<void> {
    await withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "verifyUpgrade",
        args: [newImplementation, data],
      })
    );
  }

  /*  ── write helpers ───────────────────────────────────────────────────  */

  /// Recover the signing keypair for this vault at the wallet's installed budget
  /// and confirm its commitment matches the installed one. Throws
  /// `CommitmentMismatchError` before any signature is produced.
  private recoverSigningKey(
    maxSignatures: number,
    installedCommitment: Hex
  ): ShrincsKeyPair {
    const keypair = this.signer.recoverKeyPair(this.vaultId, { maxSignatures });
    if (
      keypair.publicKeyCommitment.toLowerCase() !==
      installedCommitment.toLowerCase()
    ) {
      throw new CommitmentMismatchError(
        keypair.publicKeyCommitment,
        installedCommitment
      );
    }
    return keypair;
  }

  /// Common stateful-op preamble: assert provider, read state, recover key, pick
  /// the lowest unused leaf (or honor an explicit override).
  private async prepareStatefulOp(keyOpts?: ShrincsTxKeyOptions): Promise<{
    keypair: ShrincsKeyPair;
    state: ShrincsWalletState;
    leaf: number;
    domainSeparator: Hex;
  }> {
    await this.assertProviderBinding();
    const state = await this.getWalletState();
    const keypair = this.recoverSigningKey(
      state.maxSignatures,
      state.shrincsPublicKeyCommitment
    );
    const leaf =
      keyOpts?.leaf ??
      (await this.lowestUnusedLeaf(state.maxSignatures, state.statefulLeavesUsed));
    return {
      keypair,
      state,
      leaf,
      domainSeparator: domainSeparator(this.chainId, this.walletAddress),
    };
  }

  private async assertProviderBinding(): Promise<void> {
    await assertProviderState({
      publicClient: this.publicClient,
      expectedChainId: this.chainId,
      walletClient: this.walletClient,
      expectedAccount: this.account,
    });
  }

  private async submit(
    functionName: string,
    args: readonly unknown[],
    value: bigint,
    opts: TxOptions
  ): Promise<TransactionReceipt> {
    const contractCall = {
      address: this.walletAddress,
      abi: shrincsWalletAbi as readonly unknown[],
      functionName,
      args,
      value,
      account: this.account as Account | Address,
    };
    const prepared = await prepareTx({
      publicClient: this.publicClient,
      contractParams: contractCall,
      totalValue: value,
      opts,
    });
    const writeParams = {
      chain: boundChain(this.chainId),
      ...contractCall,
      gas: prepared.gas,
      ...prepared.fees,
      ...(prepared.nonce !== undefined && { nonce: prepared.nonce }),
    } as unknown as Parameters<WalletClient["writeContract"]>[0];
    const hash = await withDecodedError(this.walletClient.writeContract(writeParams));
    return this.publicClient.waitForTransactionReceipt({ hash });
  }

  /*  ── stateful writes ─────────────────────────────────────────────────  */

  /// Execute a single call. `value == 0 && data == "0x"` consumes a leaf without
  /// executing (emits `LeafConsumedOnly`).
  async execute(
    params: { target: Address; value?: bigint; data?: Hex },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const value = params.value ?? 0n;
    const data = params.data ?? "0x";
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts);
    const ctx = buildActionContext({
      domainSeparator: ds,
      keyVersion: state.keyVersion,
      actionType: ACTION_EXECUTE,
      payloadHash: executePayloadHash(params.target, value, keccakData(data), state.executeFee),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    return this.submit(
      "execute",
      [publicKeyToAbi(keypair.publicKey), signature, params.target, value, data],
      value + state.executeFee,
      opts
    );
  }

  /// Withdraw from the wallet's EntryPoint deposit.
  async withdrawDepositTo(
    params: { to: Address; amount: bigint },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts);
    const ctx = buildActionContext({
      domainSeparator: ds,
      keyVersion: state.keyVersion,
      actionType: ACTION_WITHDRAW,
      payloadHash: withdrawPayloadHash(params.to, params.amount),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    return this.submit(
      "withdrawDepositTo",
      [publicKeyToAbi(keypair.publicKey), signature, params.to, params.amount],
      state.executeFee,
      opts
    );
  }

  /// Top up this wallet's EntryPoint deposit. Payable and unauthenticated — no
  /// SHRINCS signature and no leaf consumed (anyone may fund the deposit). The
  /// withdrawal direction (`withdrawDepositTo`) IS SHRINCS-gated.
  async addDeposit(
    amount: bigint,
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    await this.assertProviderBinding();
    return this.submit("addDeposit", [], amount, opts);
  }

  /// Install a dedicated ERC-1271 stateless verifier key (authorized by a
  /// stateful signature from the main key).
  async setErc1271Key(
    params: { newCommitment: Hex; newParameterSetId?: ParameterSetId },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    if (
      !params.newCommitment ||
      /^0x0+$/.test(params.newCommitment)
    ) {
      throw new ZeroErc1271CommitmentError();
    }
    const paramSet = params.newParameterSetId ?? ParameterSetId.Sphincs256sKeccakQ20;
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts);
    const ctx = buildActionContext({
      domainSeparator: ds,
      keyVersion: state.keyVersion,
      actionType: ACTION_SET_ERC1271_KEY,
      payloadHash: setErc1271KeyPayloadHash(params.newCommitment, paramSet),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    return this.submit(
      "setErc1271Key",
      [publicKeyToAbi(keypair.publicKey), signature, params.newCommitment, paramSet],
      state.executeFee,
      opts
    );
  }

  /// Routine stateful rotation: refresh the stateful subkey, reuse the stateless
  /// recovery root. `nextStatefulPublicKey` is the fresh stateful key's encoded
  /// 68-byte public key (from a freshly keygen'd bundle under a new vaultId).
  async rotateKey(
    params: { nextStatefulPublicKey: Hex; nextParameterSetId?: ParameterSetId },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const paramSet = params.nextParameterSetId ?? ParameterSetId.Sphincs256sKeccakQ20;
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts);
    const nextStatefulKey = buildStatefulRotationTarget({
      parameterSetId: keypair.parameterSetId,
      nextStatefulPublicKey: params.nextStatefulPublicKey,
      currentPkSeed: keypair.publicKey.pkSeed,
      currentHypertreeRoot: keypair.publicKey.hypertreeRoot,
    });
    const ctx = buildActionContext({
      domainSeparator: ds,
      keyVersion: state.keyVersion,
      actionType: ACTION_ROTATE_KEY,
      payloadHash: rotateKeyPayloadHash(nextStatefulKey.publicKeyCommitment, paramSet),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    return this.submit(
      "rotateKey",
      [
        publicKeyToAbi(keypair.publicKey),
        signature,
        {
          parameterSetId: parameterSetIdToEnum(nextStatefulKey.parameterSetId),
          statefulPublicKey: nextStatefulKey.statefulPublicKey,
          publicKeyCommitment: nextStatefulKey.publicKeyCommitment,
        },
      ],
      state.executeFee,
      opts
    );
  }

  /// UUPS upgrade gated by a stateful signature.
  async upgradeToAndCall(
    params: {
      newImplementation: Address;
      shouldMigrate?: boolean;
      migratorPayload?: Hex;
    },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const shouldMigrate = params.shouldMigrate ?? false;
    const migratorPayload = params.migratorPayload ?? "0x";
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts);
    const ctx = buildActionContext({
      domainSeparator: ds,
      keyVersion: state.keyVersion,
      actionType: ACTION_UPGRADE,
      payloadHash: upgradePayloadHash(
        params.newImplementation,
        shouldMigrate,
        keccak256(migratorPayload)
      ),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    const data = encodeUpgradeData({
      publicKey: keypair.publicKey,
      signature,
      shouldMigrate,
      migratorPayload,
    });
    return this.submit(
      "upgradeToAndCall",
      [params.newImplementation, data],
      state.executeFee,
      opts
    );
  }

  /*  ── dual-signature & stateless writes ───────────────────────────────  */

  /// Atomic ownership handover: a fresh bundle (`nextKey`) plus a new classical
  /// owner, authorized by BOTH a stateful owner-binding signature and a stateless
  /// recovery signature from the current key.
  async transferOwnership(
    params: { nextKey: ShrincsPublicKey; newOwner: Address },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    if (params.newOwner === ZERO_ADDRESS) throw new ZeroAddressOwnerError();
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts);
    const rotationTarget = toRotationTarget(params.nextKey);

    const ownerCtx = buildActionContext({
      domainSeparator: ds,
      keyVersion: state.keyVersion,
      actionType: ACTION_TRANSFER_OWNERSHIP,
      payloadHash: transferOwnershipPayloadHash(
        params.newOwner,
        rotationTarget.publicKeyCommitment
      ),
    });
    const ownerBindingSignature = keypair.signStatefulActionAt(ownerCtx, leaf);

    const rctx = buildRotationContext({
      domainSeparator: ds,
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
    });
    const recoverySignature = keypair.signFullRotation(rctx, rotationTarget);

    return this.submit(
      "transferOwnership",
      [
        publicKeyToAbi(keypair.publicKey),
        ownerBindingSignature,
        recoverySignature,
        publicKeyToAbi(params.nextKey),
        params.newOwner,
      ],
      state.executeFee,
      opts
    );
  }

  /// Break-glass recovery: install an entirely fresh bundle authorized by the
  /// stateless recovery signature. Ownership unchanged. No leaf consumed.
  async recoverWallet(
    params: { nextKey: ShrincsPublicKey },
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    await this.assertProviderBinding();
    const state = await this.getWalletState();
    const keypair = this.recoverSigningKey(
      state.maxSignatures,
      state.shrincsPublicKeyCommitment
    );
    const rotationTarget: RotationTarget = toRotationTarget(params.nextKey);
    const rctx = buildRotationContext({
      domainSeparator: domainSeparator(this.chainId, this.walletAddress),
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
    });
    const recoverySignature = keypair.signFullRotation(rctx, rotationTarget);
    return this.submit(
      "recoverWallet",
      [publicKeyToAbi(keypair.publicKey), recoverySignature, publicKeyToAbi(params.nextKey)],
      state.executeFee,
      opts
    );
  }

  /*  ── ERC-1271 signature assembly ──────────────────────────────────────  */

  /// Assemble a full ERC-1271 signature blob for `hash`, accepted by
  /// `isValidSignature`. AND-gates two halves:
  ///   1. a SHRINCS **stateless** signature from the installed ERC-1271 verifier
  ///      key (no leaf consumed), over `ACTION_ERC1271` with `payloadHash == hash`;
  ///   2. a classical ECDSA signature from the wallet's `owner` over the EIP-712
  ///      `quipSignedHashEcdsaTarget(hash)` digest.
  /// The ERC-1271 verifier key is a separate vault branch from the main key, so
  /// the caller supplies its recovered keypair (its commitment must match the
  /// installed `erc1271Commitment`). The `owner` must be a local signer.
  async signErc1271(params: {
    hash: Hex;
    erc1271KeyPair: ShrincsKeyPair;
    owner: LocalAccount;
  }): Promise<Hex> {
    await this.assertProviderBinding();
    const state = await this.getWalletState();

    if (
      params.erc1271KeyPair.publicKeyCommitment.toLowerCase() !==
      state.erc1271Commitment.toLowerCase()
    ) {
      throw new CommitmentMismatchError(
        params.erc1271KeyPair.publicKeyCommitment,
        state.erc1271Commitment
      );
    }
    if (params.owner.address.toLowerCase() !== state.owner.toLowerCase()) {
      throw new ZeroAddressOwnerError();
    }

    // The stateless context mirrors `_checkErc1271Signature`: no-nonce, the MAIN
    // key's epoch, `ACTION_ERC1271`, and `payloadHash == hash`.
    const ctx = buildActionContext({
      domainSeparator: domainSeparator(this.chainId, this.walletAddress),
      keyVersion: state.keyVersion,
      actionType: ACTION_ERC1271,
      payloadHash: params.hash,
    });
    const statelessSignature = params.erc1271KeyPair.signStatelessAction(ctx);

    // Sign the on-chain EIP-712 target digest directly (matches the contract's
    // `ECDSA.tryRecoverCalldata(quipSignedHashEcdsaTarget(hash), ecdsaSig)`).
    const sign = params.owner.sign;
    if (!sign) {
      throw new Error(
        "owner account cannot sign a raw hash; pass a LocalAccount with a `sign` method"
      );
    }
    const ecdsaTarget = await this.quipSignedHashEcdsaTarget(params.hash);
    const ecdsaSig = await sign({ hash: ecdsaTarget });

    return encodeErc1271Signature({
      publicKey: params.erc1271KeyPair.publicKey,
      signature: statelessSignature,
      ecdsaSig,
    });
  }

  /*  ── ERC-4337 (wallet as sender) ──────────────────────────────────────  */

  /// Assemble an unsigned `PackedUserOperation` whose `callData` invokes the
  /// EntryPoint-only `execute(target, value, data)` on this wallet. Fill the
  /// signature with `signExecuteUserOp`.
  buildExecuteUserOp(
    params: ShrincsCall & UserOpEnvelope
  ): PackedUserOperation {
    const callData = encodeFunctionData({
      abi: shrincsWalletAbi,
      functionName: "execute",
      args: [params.target, params.value ?? 0n, params.data ?? "0x"],
    });
    return this.assembleUserOp(callData, params);
  }

  /// Assemble an unsigned `PackedUserOperation` whose `callData` invokes the
  /// EntryPoint-only `executeBatch(Call[])` — an atomic multi-call. A single
  /// stateful leaf authorizes the whole batch (the signature binds the
  /// `userOpHash`, which already commits to every call). Fill the signature with
  /// `signExecuteUserOp`.
  buildExecuteBatchUserOp(
    params: { calls: readonly ShrincsCall[] } & UserOpEnvelope
  ): PackedUserOperation {
    const callData = encodeFunctionData({
      abi: shrincsWalletAbi,
      functionName: "executeBatch",
      args: [
        params.calls.map((c) => ({
          target: c.target,
          value: c.value ?? 0n,
          data: c.data ?? "0x",
        })),
      ],
    });
    return this.assembleUserOp(callData, params);
  }

  /// Pack a `callData` blob into a `PackedUserOperation` with this wallet as
  /// `sender` and the supplied ERC-4337 envelope (shared by the build methods).
  private assembleUserOp(
    callData: Hex,
    env: UserOpEnvelope
  ): PackedUserOperation {
    return buildUserOp({
      sender: this.walletAddress,
      nonce: env.nonce,
      callData,
      initCode: env.initCode,
      verificationGasLimit: env.verificationGasLimit,
      callGasLimit: env.callGasLimit,
      preVerificationGas: env.preVerificationGas,
      maxFeePerGas: env.maxFeePerGas,
      maxPriorityFeePerGas: env.maxPriorityFeePerGas,
      paymasterAndData: env.paymasterAndData,
    });
  }

  /// Sign a `PackedUserOperation` for this wallet: read state, recover the key,
  /// pick the lowest unused leaf, bind the EntryPoint `userOpHash` + execute fee
  /// into `ACTION_ERC4337_EXECUTE`, and return the userOp with its `signature`
  /// field filled (plus the `userOpHash` and `leaf` used).
  async signExecuteUserOp(
    params: { userOp: PackedUserOperation; entryPoint: Address },
    opts: ShrincsTxKeyOptions = {}
  ): Promise<{ userOp: PackedUserOperation; userOpHash: Hex; leaf: number }> {
    const { keypair, state, leaf } = await this.prepareStatefulOp(opts);
    const { signature, userOpHash } = signWalletUserOp({
      keypair,
      userOp: params.userOp,
      entryPoint: params.entryPoint,
      chainId: BigInt(this.chainId),
      wallet: this.walletAddress,
      executeFee: state.executeFee,
      keyVersion: state.keyVersion,
      leaf,
    });
    return { userOp: { ...params.userOp, signature }, userOpHash, leaf };
  }
}
