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
import { HASH_SUITE_KECCAK_256 } from "./constants.js";
import {
  AuthLeafInTargetsError,
  CommitmentMismatchError,
  EmptyLeavesError,
  Erc1271ValidationResult,
  LeafOutOfRangeError,
  OwnerMismatchError,
  StatefulBudgetExhaustedError,
  ZeroAddressOwnerError,
  ZeroErc1271CommitmentError,
} from "./errors.js";
import { prepareTx, type TxOptions } from "./gas.js";
import {
  LeafReservationStore,
  reserveExplicitLeaf,
  reserveLowestLeaf,
} from "./leafReservation.js";
import { assertReceiptSuccess } from "./internal/assertReceiptSuccess.js";
import { withDecodedError } from "./internal/decodeError.js";
import {
  ACTION_ERC1271,
  ACTION_EXECUTE,
  ACTION_MARK_LEAVES_USED,
  ACTION_ROTATE_KEY,
  ACTION_SET_ERC1271_KEY,
  ACTION_TRANSFER_OWNERSHIP,
  ACTION_UPGRADE,
  ACTION_WITHDRAW,
  ROTATION_DOMAIN_RECOVER_WALLET,
  ROTATION_DOMAIN_TRANSFER_OWNERSHIP,
  buildActionContext,
  buildRotationContext,
  buildStatefulRotationTarget,
  dataHash as keccakData,
  domainSeparator,
  encodeErc1271Signature,
  encodeUpgradeData,
  executePayloadHash,
  leavesHash,
  markLeavesUsedPayloadHash,
  publicKeyToAbi,
  rotateKeyPayloadHash,
  rotationDomainSeparator,
  setErc1271KeyPayloadHash,
  SHRINCS_PROFILE_NAME,
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
  computeUserOpHash,
  signWalletUserOp,
} from "./userOp.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;

const shrincsWalletDomain = (chainId: number, walletAddress: Address) =>
  ({
    name: `QuipShrincsWallet/${SHRINCS_PROFILE_NAME}/v1`,
    version: "1",
    chainId,
    verifyingContract: walletAddress,
  }) as const;

/// EIP-712 form of the owner userOp co-signature digest. Mirrors the contract's
/// `quipUserOpHashEcdsaTarget`, but signable via `eth_signTypedData_v4` — so
/// browser wallets can co-sign without the disabled `eth_sign`.
export const quipUserOpHashTypedData = (
  userOpHash: Hex,
  chainId: number,
  walletAddress: Address
) =>
  ({
    domain: shrincsWalletDomain(chainId, walletAddress),
    types: { QuipUserOpHash: [{ name: "userOpHash", type: "bytes32" }] },
    primaryType: "QuipUserOpHash",
    message: { userOpHash },
  }) as const;

/// EIP-712 form of the ERC-1271 owner-signature digest. Mirrors the contract's
/// `quipSignedHashEcdsaTarget`, but signable via `eth_signTypedData_v4`. Its
/// struct (`QuipSignedHash`) is deliberately distinct from `QuipUserOpHash`, so
/// a dApp-harvested message signature can never double as a userOp co-signature.
export const quipSignedHashTypedData = (
  hash: Hex,
  chainId: number,
  walletAddress: Address
) =>
  ({
    domain: shrincsWalletDomain(chainId, walletAddress),
    types: { QuipSignedHash: [{ name: "hash", type: "bytes32" }] },
    primaryType: "QuipSignedHash",
    message: { hash },
  }) as const;

export interface ShrincsWalletState {
  owner: Address;
  version: bigint;
  executeFee: bigint;
  shrincsPublicKeyCommitment: Hex;
  erc1271Commitment: Hex;
  hashSuite: number;
  erc1271HashSuite: number;
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
  signer?: ShrincsSigner;
  keypair?: ShrincsKeyPair;
  vaultId: Hex;
  chainId: number;
  account: Address;
}

export async function fetchShrincsWalletState(
  publicClient: PublicClient,
  walletAddress: Address
): Promise<ShrincsWalletState> {
  const fns = [
    "owner",
    "version",
    "getExecuteFee",
    "getShrincsPublicKeyCommitment",
    "getErc1271Commitment",
    "getHashSuite",
    "getErc1271HashSuite",
    "keyVersion",
    "actionNonce",
    "maxSignatures",
    "statefulLeavesUsed",
    "remainingStatefulSignatures",
  ] as const;
  const results = await tryMulticall(
    publicClient,
    fns.map((functionName) => ({
      address: walletAddress,
      abi: shrincsWalletAbi,
      functionName,
    }))
  );
  const get = (i: number) => {
    const r = results[i];
    if (!r || r.status !== "success") {
      throw new Error(`Failed to read ${fns[i]} from ${walletAddress}`);
    }
    return r.result as never;
  };
  return {
    owner: get(0),
    version: BigInt(get(1)),
    executeFee: BigInt(get(2)),
    shrincsPublicKeyCommitment: get(3),
    erc1271Commitment: get(4),
    hashSuite: Number(get(5)),
    erc1271HashSuite: Number(get(6)),
    keyVersion: BigInt(get(7)),
    actionNonce: BigInt(get(8)),
    maxSignatures: Number(get(9)),
    statefulLeavesUsed: Number(get(10)),
    remainingStatefulSignatures: Number(get(11)),
  };
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
  private readonly signer?: ShrincsSigner;
  private readonly keypair?: ShrincsKeyPair;
  /// Per-instance record of leaves already handed out for signing this session,
  /// so a sign-then-retry (changed payload, first tx not yet landed) cannot pick
  /// the same leaf twice and reuse a one-time signature.
  private readonly leafReservations = new LeafReservationStore();

  constructor(params: ShrincsWalletClientParams) {
    this.walletAddress = params.walletAddress;
    this.publicClient = params.publicClient;
    this.walletClient = params.walletClient;
    this.signer = params.signer;
    this.keypair = params.keypair;
    this.vaultId = params.vaultId;
    this.chainId = params.chainId;
    this.account = params.account;
  }

  /*  ── reads ───────────────────────────────────────────────────────────  */

  /// Atomic snapshot of wallet state via Multicall3 (sequential fallback).
  async getWalletState(): Promise<ShrincsWalletState> {
    return fetchShrincsWalletState(this.publicClient, this.walletAddress);
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
  /// `StatefulBudgetExhaustedError` if every leaf is consumed (or every free
  /// leaf is excluded). `exclude` skips leaves the bitmap considers free but
  /// that must not sign — e.g. `markLeavesUsed` targets, whose one-time keys
  /// have typically already signed an off-chain message.
  async lowestUnusedLeaf(
    maxSignatures: number,
    statefulLeavesUsed: number,
    exclude?: ReadonlySet<number>
  ): Promise<number> {
    if (statefulLeavesUsed >= maxSignatures) {
      throw new StatefulBudgetExhaustedError(maxSignatures, statefulLeavesUsed);
    }
    const used = await this.fetchUsedLeaves(maxSignatures);
    for (let leaf = 1; leaf <= maxSignatures; leaf++) {
      if (exclude?.has(leaf)) continue;
      if (!used.has(leaf)) return leaf;
    }
    throw new StatefulBudgetExhaustedError(maxSignatures, statefulLeavesUsed);
  }

  /// The set of `1..maxSignatures` leaves the on-chain bitmap reports as used,
  /// read in one multicall. A leaf whose status could not be read is treated as
  /// used: never sign at a leaf that is not confirmed free.
  private async fetchUsedLeaves(maxSignatures: number): Promise<Set<number>> {
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
    const used = new Set<number>();
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (!(r && r.status === "success" && r.result === false)) used.add(i + 1);
    }
    return used;
  }

  /// The WalletFactory that deployed this wallet (the remaining `IShrincsWallet`
  /// view not bundled into `getWalletState`).
  async walletFactory(): Promise<Address> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "walletFactory",
      })
    ) as Promise<Address>;
  }

  /// The pinned external SHRINCS verifier (an implementation immutable) every
  /// signature check is delegated to.
  async getShrincsVerifier(): Promise<Address> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "getShrincsVerifier",
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

  /// The EIP-712 typed-data digest the owner's userOp ECDSA co-signature must
  /// sign (deliberately a distinct domain from `quipSignedHashEcdsaTarget`, so
  /// an ERC-1271 message signature can never double as a userOp co-signature).
  /// Read from chain so it always matches the deployed domain.
  async quipUserOpHashEcdsaTarget(userOpHash: Hex): Promise<Hex> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "quipUserOpHashEcdsaTarget",
        args: [userOpHash],
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
    const keypair =
      this.keypair ?? this.signer?.recoverKeyPair(this.vaultId, { maxSignatures });
    if (!keypair) {
      throw new Error("ShrincsWalletClient has no signer or keypair to sign with");
    }
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
  /// the lowest unused leaf (or honor an explicit override). `excludeLeaves`
  /// constrains only the automatic pick; callers with an explicit `keyOpts.leaf`
  /// are responsible for their own exclusion guard (see `markLeavesUsed`).
  private async prepareStatefulOp(
    keyOpts?: ShrincsTxKeyOptions,
    excludeLeaves?: ReadonlySet<number>
  ): Promise<{
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
    // Reserve the leaf in-process before signing so a sign-then-retry with a
    // changed payload (first tx not yet landed, bitmap still shows the leaf
    // free) cannot sign a second message at the same one-time leaf. An explicit
    // override is reserved too, so a later automatic pick cannot collide with it.
    const reservationKey = {
      commitment: state.shrincsPublicKeyCommitment,
      keyVersion: state.keyVersion,
    };
    let leaf: number;
    if (keyOpts?.leaf !== undefined) {
      leaf = keyOpts.leaf;
      await reserveExplicitLeaf(this.leafReservations, reservationKey, leaf);
    } else {
      if (state.statefulLeavesUsed >= state.maxSignatures) {
        throw new StatefulBudgetExhaustedError(
          state.maxSignatures,
          state.statefulLeavesUsed
        );
      }
      const used = await this.fetchUsedLeaves(state.maxSignatures);
      leaf = await reserveLowestLeaf(
        this.leafReservations,
        reservationKey,
        (candidate) =>
          used.has(candidate) || (excludeLeaves?.has(candidate) ?? false),
        state.maxSignatures
      );
    }
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
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return assertReceiptSuccess(receipt);
  }

  /*  ── stateful writes ─────────────────────────────────────────────────  */

  /// Execute a single call. `value == 0 && data == "0x"` consumes a leaf without
  /// executing (emits `LeafConsumedOnly`).
  ///
  /// FEE CAP — `maxFee` (default: the live `executeFee` at prepare time) is the
  /// signed CEILING, not the charged amount: the wallet charges the live fee at
  /// landing and reverts `ExecuteFeeExceedsCap` only if it exceeds the cap. A
  /// fee decrease between signing and landing succeeds at the lower price; pass
  /// a higher `maxFee` for headroom against increases.
  async execute(
    params: { target: Address; value?: bigint; data?: Hex; maxFee?: bigint },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const value = params.value ?? 0n;
    const data = params.data ?? "0x";
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts);
    const maxFee = params.maxFee ?? state.executeFee;
    const ctx = buildActionContext({
      domainSeparator: ds,
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
      actionType: ACTION_EXECUTE,
      payloadHash: executePayloadHash(params.target, value, keccakData(data), maxFee),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    // msg.value funds the ceiling; any excess over the live fee stays in the
    // wallet (the user's own funds), and the call cannot underfund a fee move
    // within the cap.
    return this.submit(
      "execute",
      [publicKeyToAbi(keypair.publicKey), signature, params.target, value, data, maxFee],
      value + maxFee,
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
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
      actionType: ACTION_WITHDRAW,
      payloadHash: withdrawPayloadHash(params.to, params.amount),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    return this.submit(
      "withdrawDepositTo",
      [publicKeyToAbi(keypair.publicKey), signature, params.to, params.amount],
      0n,
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
    params: { newCommitment: Hex; newHashSuite?: number },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    if (
      !params.newCommitment ||
      /^0x0+$/.test(params.newCommitment)
    ) {
      throw new ZeroErc1271CommitmentError();
    }
    const hashSuite = params.newHashSuite ?? HASH_SUITE_KECCAK_256;
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts);
    const ctx = buildActionContext({
      domainSeparator: ds,
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
      actionType: ACTION_SET_ERC1271_KEY,
      payloadHash: setErc1271KeyPayloadHash(params.newCommitment, hashSuite),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    return this.submit(
      "setErc1271Key",
      [publicKeyToAbi(keypair.publicKey), signature, params.newCommitment, hashSuite],
      0n,
      opts
    );
  }

  /// Routine stateful rotation: refresh the stateful subkey, reuse the stateless
  /// recovery root. `nextStatefulPublicKey` is the fresh stateful key's encoded
  /// 68-byte public key (from a freshly keygen'd bundle under a new vaultId).
  async rotateKey(
    params: { nextStatefulPublicKey: Hex },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts);
    const nextStatefulKey = buildStatefulRotationTarget({
      nextStatefulPublicKey: params.nextStatefulPublicKey,
      currentPkSeed: keypair.publicKey.pkSeed,
      currentHypertreeRoot: keypair.publicKey.hypertreeRoot,
    });
    const ctx = buildActionContext({
      domainSeparator: ds,
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
      actionType: ACTION_ROTATE_KEY,
      payloadHash: rotateKeyPayloadHash(nextStatefulKey.publicKeyCommitment),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    return this.submit(
      "rotateKey",
      [
        publicKeyToAbi(keypair.publicKey),
        signature,
        {
          statefulPublicKey: nextStatefulKey.statefulPublicKey,
          publicKeyCommitment: nextStatefulKey.publicKeyCommitment,
        },
      ],
      0n,
      opts
    );
  }

  /// Surgical batch leaf revocation: mark the target leaves used in the current
  /// key epoch's bitmap, authorized by one stateful signature from a DIFFERENT
  /// leaf. OTS hygiene — burn a leaf whose one-time key signed a message that
  /// will never land, or kill a specific outstanding approval.
  ///
  /// SURGICAL — unlike every other landed action, this does NOT advance the
  /// action nonce, so outstanding signed material at non-revoked leaves stays
  /// valid. On-chain skip semantics: already-used targets (races, duplicates)
  /// emit `LeafRevocationSkipped` instead of reverting; out-of-range targets
  /// revert `LeafOutOfRange`; an empty array reverts `EmptyLeaves`.
  ///
  /// The authorizing leaf is auto-picked OUTSIDE the target set: a leaf being
  /// revoked has typically already signed off-chain, and authorizing with it
  /// would be exactly the key reuse this call prevents. An explicit `opts.leaf`
  /// inside the targets throws `AuthLeafInTargetsError` before signing.
  async markLeavesUsed(
    params: { leaves: readonly number[] },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const leaves = params.leaves;
    if (leaves.length === 0) throw new EmptyLeavesError();
    const targetSet = new Set(leaves);
    if (opts.leaf !== undefined && targetSet.has(opts.leaf)) {
      throw new AuthLeafInTargetsError(opts.leaf);
    }
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts, targetSet);
    // All guards run BEFORE signing: a signed-then-aborted call would itself
    // leave a leaf needing revocation.
    for (const target of leaves) {
      if (
        !Number.isInteger(target) ||
        target < 1 ||
        target > state.maxSignatures
      ) {
        throw new LeafOutOfRangeError(target, state.maxSignatures);
      }
    }
    const ctx = buildActionContext({
      domainSeparator: ds,
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
      actionType: ACTION_MARK_LEAVES_USED,
      payloadHash: markLeavesUsedPayloadHash(leavesHash(leaves)),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    return this.submit(
      "markLeavesUsed",
      [publicKeyToAbi(keypair.publicKey), signature, [...leaves]],
      0n,
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
      nonce: state.actionNonce,
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
      // Must be the same live nonce the context above bound (the wallet's
      // StaleActionNonce gate checks blob nonce == actionNonce()).
      nonce: state.actionNonce,
    });
    return this.submit(
      "upgradeToAndCall",
      [params.newImplementation, data],
      0n,
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
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
      actionType: ACTION_TRANSFER_OWNERSHIP,
      payloadHash: transferOwnershipPayloadHash(
        params.newOwner,
        rotationTarget.publicKeyCommitment
      ),
    });
    const ownerBindingSignature = keypair.signStatefulActionAt(ownerCtx, leaf);

    // Handover-tagged rotation domain — this signature can never double as a
    // `recoverWallet` input (see `rotationDomainSeparator`).
    const rctx = buildRotationContext({
      domainSeparator: rotationDomainSeparator(
        ds,
        ROTATION_DOMAIN_TRANSFER_OWNERSHIP
      ),
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
      0n,
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
      domainSeparator: rotationDomainSeparator(
        domainSeparator(this.chainId, this.walletAddress),
        ROTATION_DOMAIN_RECOVER_WALLET
      ),
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
    });
    const recoverySignature = keypair.signFullRotation(rctx, rotationTarget);
    return this.submit(
      "recoverWallet",
      [publicKeyToAbi(keypair.publicKey), recoverySignature, publicKeyToAbi(params.nextKey)],
      0n,
      opts
    );
  }

  /*  ── ERC-1271 signature assembly ──────────────────────────────────────  */

  /// Assemble a full ERC-1271 signature blob for `hash`, accepted by
  /// `isValidSignature`. AND-gates two halves:
  ///   1. a SHRINCS **stateless** signature from the installed ERC-1271 verifier
  ///      key (no leaf consumed), over `ACTION_ERC1271` with `payloadHash == hash`;
  ///   2. a classical ECDSA signature from the wallet's `owner` over the
  ///      `QuipSignedHash(hash)` EIP-712 target (collected as typed data, so a
  ///      browser wallet can sign it via `eth_signTypedData_v4`).
  /// The ERC-1271 verifier key is a separate vault branch from the main key, so
  /// the caller supplies its recovered keypair (its commitment must match the
  /// installed `erc1271Commitment`). The `owner` must sign for the wallet's
  /// on-chain `owner()`.
  ///
  /// FRESHNESS: the blob binds the wallet's LIVE `actionNonce()`, so it is
  /// invalidated the moment ANY wallet signature is consumed (an execute, a
  /// rotation, a sponsored userOp, ...). Sign as late as possible and re-sign
  /// after wallet actions.
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
    if (params.owner.address.toLowerCase() === ZERO_ADDRESS) {
      throw new ZeroAddressOwnerError();
    }
    if (params.owner.address.toLowerCase() !== state.owner.toLowerCase()) {
      throw new OwnerMismatchError(state.owner, params.owner.address);
    }

    // The stateless context mirrors `_checkErc1271Signature`: the LIVE action
    // nonce, the MAIN key's epoch, `ACTION_ERC1271`, and `payloadHash == hash`.
    const ctx = buildActionContext({
      domainSeparator: domainSeparator(this.chainId, this.walletAddress),
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
      actionType: ACTION_ERC1271,
      payloadHash: params.hash,
    });
    const statelessSignature = params.erc1271KeyPair.signStatelessAction(ctx);

    // Owner ECDSA half, collected as typed data (see `quipSignedHashTypedData`).
    const ecdsaSig = await params.owner.signTypedData(
      quipSignedHashTypedData(params.hash, this.chainId, this.walletAddress)
    );

    return encodeErc1271Signature({
      publicKey: params.erc1271KeyPair.publicKey,
      signature: statelessSignature,
      ecdsaSig,
    });
  }

  /*  ── ERC-4337 (wallet as sender) ──────────────────────────────────────  */

  /// Assemble an unsigned `PackedUserOperation` whose `callData` invokes the
  /// EntryPoint-only `execute(target, value, data, maxFee)` on this wallet.
  /// `maxFee` is the signed execution-fee ceiling: it rides in `callData`, so
  /// signing the userOp binds it with no digest work (typically the live
  /// `executeFee`, e.g. from `getWalletState()`; higher for headroom). Fill
  /// the signature with `signExecuteUserOp`.
  buildExecuteUserOp(
    params: ShrincsCall & UserOpEnvelope & { maxFee: bigint }
  ): PackedUserOperation {
    const callData = encodeFunctionData({
      abi: shrincsWalletAbi,
      functionName: "execute",
      args: [params.target, params.value ?? 0n, params.data ?? "0x", params.maxFee],
    });
    return this.assembleUserOp(callData, params);
  }

  /// Assemble an unsigned `PackedUserOperation` whose `callData` invokes the
  /// EntryPoint-only `executeBatch(Call[], maxFee)` — an atomic multi-call. A
  /// single stateful leaf authorizes the whole batch (the signature binds the
  /// `userOpHash`, which already commits to every call) and a single `maxFee`
  /// caps the one per-batch fee. Fill the signature with `signExecuteUserOp`.
  buildExecuteBatchUserOp(
    params: { calls: readonly ShrincsCall[]; maxFee: bigint } & UserOpEnvelope
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
        params.maxFee,
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
  /// pick the lowest unused leaf, bind the EntryPoint `userOpHash` + live
  /// `actionNonce` into `ACTION_ERC4337_EXECUTE`, collect the owner's ECDSA
  /// co-signature as EIP-712 typed data (every userOp is hybrid — validation
  /// requires BOTH the owner key and the SHRINCS key), and return the userOp
  /// with its `signature` field filled (plus the `userOpHash` and `leaf` used).
  /// The `owner` must sign for the wallet's on-chain `owner()`.
  ///
  /// FEE CAP: no fee enters the digest — the `maxFee` ceiling the build methods
  /// put into `callData` is covered by `userOpHash`, and validation reads no
  /// fee (ERC-7562). If the live fee rises past the signed cap before landing,
  /// the op still validates and the EXECUTION phase reverts — consuming the
  /// leaf and advancing the nonce (inherent to validation-phase stateful
  /// signatures); sign with headroom if fee changes are a concern.
  ///
  /// SERIALIZATION: the bound action nonce advances when any wallet signature is
  /// consumed, so ops must land in signing order — signing a second op before
  /// the first lands binds a stale nonce and it will be rejected (AA24).
  async signExecuteUserOp(
    params: {
      userOp: PackedUserOperation;
      entryPoint: Address;
      owner: LocalAccount;
    },
    opts: ShrincsTxKeyOptions = {}
  ): Promise<{ userOp: PackedUserOperation; userOpHash: Hex; leaf: number }> {
    const { keypair, state, leaf } = await this.prepareStatefulOp(opts);

    if (params.owner.address.toLowerCase() === ZERO_ADDRESS) {
      throw new ZeroAddressOwnerError();
    }
    if (params.owner.address.toLowerCase() !== state.owner.toLowerCase()) {
      throw new OwnerMismatchError(state.owner, params.owner.address);
    }
    // Recompute the userOpHash exactly as `signWalletUserOp` does below, then
    // collect the owner co-signature over it as typed data.
    const userOpHash = computeUserOpHash(
      params.userOp,
      params.entryPoint,
      BigInt(this.chainId)
    );
    const ownerEcdsaSig = await params.owner.signTypedData(
      quipUserOpHashTypedData(userOpHash, this.chainId, this.walletAddress)
    );

    const { signature } = signWalletUserOp({
      keypair,
      userOp: params.userOp,
      entryPoint: params.entryPoint,
      chainId: BigInt(this.chainId),
      wallet: this.walletAddress,
      keyVersion: state.keyVersion,
      leaf,
      actionNonce: state.actionNonce,
      ownerEcdsaSig,
    });
    return { userOp: { ...params.userOp, signature }, userOpHash, leaf };
  }
}
