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
  bytesToHex,
  encodeFunctionData,
  keccak256,
  recoverTypedDataAddress,
} from "viem";

import { assertProviderState, boundChain } from "../internal/providerState.js";
import { tryMulticall } from "../internal/multicall.js";
import { shrincsWalletAbi } from "./abi/ShrincsWallet.js";
import { HASH_SUITE_KECCAK_256 } from "./constants.js";
import { assertHdIndex } from "./hd.js";
import {
  AuthLeafInTargetsError,
  CommitmentMismatchError,
  EmptyLeavesError,
  Erc1271ValidationResult,
  LeafOutOfRangeError,
  ExecuteTargetHasNoCodeError,
  InvalidKeyAcceptanceError,
  InvalidOwnerAcceptanceError,
  OwnerMismatchError,
  StatefulBudgetExhaustedError,
  StatefulTreeSpentError,
  StatelessTreeSpentError,
  UnsupportedByWalletVersionError,
  ZeroAddressOwnerError,
} from "./errors.js";
import { prepareTx, type ContractCallParams, type TxOptions } from "./gas.js";
import { type CostEstimate, estimateTxCost } from "./estimateCost.js";
import {
  LeafReservationStore,
  reserveExplicitLeaf,
  reserveLowestLeaf,
} from "./leafReservation.js";
import { assertReceiptSuccess } from "./internal/assertReceiptSuccess.js";
import {
  bitmapWordCount,
  usedLeavesFromWords,
  wordsFromResults,
} from "./internal/leafBitmap.js";
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
  buildOwnershipAcceptanceContext,
  buildRotationContext,
  buildStatefulRotationTarget,
  dataHash as keccakData,
  decodeInitPayload,
  domainSeparator,
  encodeErc1271Signature,
  encodeProbeVector,
  encodeUpgradeData,
  executePayloadHash,
  probeDigest,
  leavesHash,
  markLeavesUsedPayloadHash,
  publicKeyToAbi,
  rotateKeyPayloadHash,
  rotationDomainSeparator,
  setErc1271KeyPayloadHash,
  SHRINCS_PROFILE_NAME,
  statefulActionMessageHash,
  statefulMaxSignatures,
  statefulRawMessageHash,
  statelessRawMessageHash,
  statefulTreeId,
  statelessTreeId,
  toRotationTarget,
  transferOwnershipPayloadHash,
  upgradePayloadHash,
  withdrawPayloadHash,
} from "./shrincsCodec.js";
import { type ShrincsKeyPair, type ShrincsSigner } from "./shrincsSigner.js";
import {
  type RotationTarget,
  type ShrincsPublicKey,
  type StatefulSignature,
} from "./types.js";
import {
  type WalletVersionDescriptor,
  resolveWalletVersionFromChain,
} from "./versions/index.js";
import {
  type PackedUserOperation,
  buildUserOp,
  computeUserOpHash,
  signWalletUserOp,
} from "./userOp.js";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;

/// Signing budget for a throwaway `verifyUpgrade` probe bundle. The probe bundle
/// is single-use and verified only against its OWN commitment, so a tiny tree
/// suffices; it signs the target digest once (at leaf 1).
const PROBE_MAX_SIGNATURES = 4;
const PROBE_LEAF = 1;

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

/// The INCOMING party's half of a `transferOwnership` handover: proof that
/// whoever receives the wallet controls BOTH keys it will be operated with.
/// Produced by the recipient (`signOwnershipAcceptance`), handed to the current
/// owner alongside the bundle, and verified on-chain before the install.
export interface OwnershipAcceptance {
  /// The recipient's fresh full key bundle (both trees never held by the wallet).
  nextKey: ShrincsPublicKey;
  /// The incoming classical owner.
  newOwner: Address;
  /// Stateful signature by `nextKey` over the handover payload, bound to
  /// `nextKey`'s own commitment at nonce 0 / keyVersion 0
  /// (`buildOwnershipAcceptanceContext`). Its leaf is spent in the new epoch.
  keyAcceptance: StatefulSignature;
  /// `newOwner`'s signature over the wallet's
  /// `QuipSignedHash(transferOwnershipPayloadHash(newOwner, nextCommitment))`
  /// EIP-712 target (ECDSA for an EOA; ERC-1271 for a contract owner).
  ownerAcceptance: Hex;
}

/// RECIPIENT side of a `transferOwnership` handover. Signs both halves of the
/// acceptance for `walletAddress` on `chainId`: the classical half via
/// `signTypedData` on the wallet's `QuipSignedHash` struct (so a browser or
/// hardware wallet can sign it), and the PQ half with the incoming bundle at
/// `leaf` (default 1). Needs no wallet client and no on-chain read: the
/// acceptance binds neither the nonce nor the epoch, only the wallet, chain,
/// `newOwner` and the bundle's commitment — which the wallet can install once.
///
/// ONE handover per bundle. The PQ half is a one-time signature at `leaf`; a
/// second acceptance with the same bundle (another wallet, another owner)
/// would sign a different message at the same leaf. Keygen a fresh bundle per
/// handover, and note the wallet records `leaf` as used once installed.
export async function signOwnershipAcceptance(params: {
  chainId: number;
  walletAddress: Address;
  nextKeyPair: ShrincsKeyPair;
  newOwner: LocalAccount;
  leaf?: number;
}): Promise<OwnershipAcceptance> {
  const newOwner = params.newOwner.address;
  if (newOwner.toLowerCase() === ZERO_ADDRESS) throw new ZeroAddressOwnerError();
  const nextKey = params.nextKeyPair.publicKey;
  const payloadHash = transferOwnershipPayloadHash(
    newOwner,
    nextKey.publicKeyCommitment
  );
  const keyAcceptance = params.nextKeyPair.signOwnershipAcceptance(
    domainSeparator(params.chainId, params.walletAddress),
    newOwner,
    params.leaf ?? 1
  );
  const ownerAcceptance = await params.newOwner.signTypedData(
    quipSignedHashTypedData(payloadHash, params.chainId, params.walletAddress)
  );
  return { nextKey, newOwner, keyAcceptance, ownerAcceptance };
}

export interface ShrincsWalletState {
  owner: Address;
  version: bigint;
  executeFee: bigint;
  shrincsPublicKeyCommitment: Hex;
  erc1271PublicKeyCommitment: Hex;
  hashSuite: number;
  erc1271HashSuite: number;
  keyVersion: bigint;
  actionNonce: bigint;
  maxSignatures: number;
  statefulLeavesUsed: number;
  remainingStatefulSignatures: number;
}

export interface ExecuteParams {
  target: Address;
  value?: bigint;
  data?: Hex;
  maxFee?: bigint;
}

export interface ExecuteCostEstimate extends CostEstimate {
  executeFee: bigint;
}

/// An `execute` that has been signed ONCE and priced, but not sent. The leaf
/// is reserved in this client instance and the signature exists only in
/// memory until `send()` broadcasts exactly those bytes. See `prepareExecute`.
export interface PreparedExecute {
  /// The one-time leaf this op is signed at.
  leaf: number;
  /// The signed fee ceiling (`params.maxFee`, or the live fee at prepare time).
  maxFee: bigint;
  /// The live `executeFee` read at prepare time.
  executeFee: bigint;
  /// ETH the sender attaches: `value + maxFee`.
  totalValue: bigint;
  /// `eth_estimateGas` of the signed call with the sender's balance overridden,
  /// so the quote does not depend on the account currently being funded.
  estimate: ExecuteCostEstimate;
  /// Broadcast the prepared call and wait for its receipt. One-shot: a second
  /// call throws rather than re-signing or re-sending.
  send(): Promise<TransactionReceipt>;
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
  commitment: Hex;
  /// Caller-chosen key-derivation index. Required when recovering a keypair
  /// from `signer` (no injected `keypair`). Unused when `keypair` is provided.
  derivationIndex?: number;
  chainId: number;
  account: Address;
}

export async function fetchShrincsWalletState(
  publicClient: PublicClient,
  walletAddress: Address,
  version?: WalletVersionDescriptor
): Promise<ShrincsWalletState> {
  // Resolve the wallet's deployed generation so reads use the RIGHT ABI + getter
  // names. A V1.0.1-beta.2 wallet exposes `getErc1271Commitment`, not the later
  // `getErc1271PublicKeyCommitment`; reading the wrong name reverts and would
  // otherwise make EVERY operation (upgrade included) fail against beta.2.
  const resolved =
    version ?? (await resolveWalletVersionFromChain(publicClient, walletAddress));
  const erc1271CommitmentGetter = resolved.quirks.erc1271CommitmentGetter;
  const fns = [
    "owner",
    "version",
    "getExecuteFee",
    "getShrincsPublicKeyCommitment",
    erc1271CommitmentGetter,
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
      abi: resolved.abi,
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
    erc1271PublicKeyCommitment: get(4),
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
  readonly commitment: Hex;
  readonly derivationIndex?: number;

  private readonly publicClient: PublicClient;
  private readonly walletClient: WalletClient;
  private readonly signer?: ShrincsSigner;
  private readonly keypair?: ShrincsKeyPair;
  /// Memoized deployed generation of this wallet (see `resolveVersion`).
  private walletVersion?: WalletVersionDescriptor;
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
    this.commitment = params.commitment;
    if (params.derivationIndex !== undefined) {
      assertHdIndex(params.derivationIndex, "derivationIndex");
    }
    this.derivationIndex = params.derivationIndex;
    this.chainId = params.chainId;
    this.account = params.account;
  }

  /*  ── reads ───────────────────────────────────────────────────────────  */

  /// Atomic snapshot of wallet state via Multicall3 (sequential fallback).
  async getWalletState(): Promise<ShrincsWalletState> {
    return fetchShrincsWalletState(
      this.publicClient,
      this.walletAddress,
      await this.resolveVersion()
    );
  }

  /// The wallet's deployed generation, resolved once (from its installed
  /// implementation) and memoized. Selects the version-correct ABI + getter
  /// names so the SDK keeps operating and UPGRADING older on-chain wallets.
  async resolveVersion(): Promise<WalletVersionDescriptor> {
    if (!this.walletVersion) {
      this.walletVersion = await resolveWalletVersionFromChain(
        this.publicClient,
        this.walletAddress
      );
    }
    return this.walletVersion;
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

  /// Lowest unused stateful signing leaf in `1..maxSignatures` for the current
  /// key epoch, found by scanning the on-chain bitmap via multicall. Throws
  /// `StatefulBudgetExhaustedError` if every signing leaf is consumed (or every
  /// free leaf is excluded). `exclude` skips leaves the bitmap considers free
  /// but that must not sign — e.g. `markLeavesUsed` targets, whose one-time keys
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

  /// The set of signing leaves in `1..maxSignatures` the on-chain bitmap
  /// reports as used, read one 256-bit word per call via
  /// `statefulLeafBitmapWord` (256 leaves per call instead of one). Throws
  /// `LeafBitmapReadError` if any word cannot be read: an unread word leaves the
  /// used state of its 256 leaves unknown, and signing at a leaf that is not
  /// confirmed free risks one-time-signature reuse.
  private async fetchUsedLeaves(maxSignatures: number): Promise<Set<number>> {
    const wordCount = bitmapWordCount(maxSignatures);
    if (wordCount === 0) return new Set();
    const calls = [];
    for (let word = 0; word < wordCount; word++) {
      calls.push({
        address: this.walletAddress,
        abi: shrincsWalletAbi,
        functionName: "statefulLeafBitmapWord" as const,
        args: [BigInt(word)] as const,
      });
    }
    const results = await tryMulticall(this.publicClient, calls);
    return usedLeavesFromWords(wordsFromResults(results), maxSignatures);
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

  /// Pre-flight the `verifyUpgrade` reachability probe as a staticcall against
  /// the NEW IMPLEMENTATION — exactly the contract, and the exact bytes, the
  /// wallet forwards during `upgradeToAndCall` (the deployed beta.2 caller
  /// forwards the WHOLE `data` blob; the target's `verifyUpgrade` shape-sniffs
  /// `0xc0` and unwraps it). Resolves if the target accepts `data`, otherwise
  /// throws the decoded contract error. Run before `upgradeToAndCall`.
  async verifyUpgrade(newImplementation: Address, data: Hex): Promise<void> {
    await withDecodedError(
      this.publicClient.readContract({
        address: newImplementation,
        abi: shrincsWalletAbi,
        functionName: "verifyUpgrade",
        args: [newImplementation, data],
      })
    );
  }

  /// Build the bare `verifyUpgrade` probe vector for `newImplementation`: a
  /// SEPARATE throwaway SHRINCS bundle signs the recomputed `probeDigest` under
  /// both halves. It is deliberately NOT the wallet's own key — signing two
  /// different messages (the upgrade authorization AND the probe digest) at one
  /// leaf of the same tree would expose that leaf's one-time key. Requires a
  /// `signer` to derive the throwaway bundle.
  buildUpgradeProbeVector(newImplementation: Address): Hex {
    if (!this.signer) {
      throw new Error(
        "upgradeToAndCall requires a signer to build the verifyUpgrade probe vector"
      );
    }
    const seed = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    const probe = this.signer.keygenFromSeedHex(seed, {
      maxSignatures: PROBE_MAX_SIGNATURES,
    });
    const digest = probeDigest(newImplementation);
    const commitment = probe.publicKeyCommitment;
    const statefulSig = probe.signStatefulRawAt(
      statefulRawMessageHash(commitment, digest),
      PROBE_LEAF
    );
    const statelessSig = probe.signStatelessRaw(
      statelessRawMessageHash(commitment, digest)
    );
    return encodeProbeVector({
      bundle: probe.publicKey,
      statefulSig,
      statelessSig,
    });
  }

  /*  ── write helpers ───────────────────────────────────────────────────  */

  /// Recover the signing keypair for this wallet at the installed budget
  /// and confirm its commitment matches the installed one. Throws
  /// `CommitmentMismatchError` before any signature is produced.
  private recoverSigningKey(
    maxSignatures: number,
    installedCommitment: Hex
  ): ShrincsKeyPair {
    let keypair = this.keypair;
    if (!keypair) {
      const derivationIndex = this.derivationIndex;
      if (derivationIndex === undefined) {
        throw new Error(
          "ShrincsWalletClient has no derivationIndex to recover a keypair with"
        );
      }
      keypair = this.signer?.recoverKeyPair(derivationIndex, { maxSignatures });
    }
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

  /// Pre-flight mirror of the wallet's spent-tree registry for the one case the
  /// client can see: the next stateful tree equals the INSTALLED one (same
  /// tree, or the same tree under a re-declared budget). Cycles back to an
  /// older tree are only caught on-chain (`StatefulTreeSpentError` decoded).
  private assertFreshStatefulTree(nextStatefulPublicKey: Hex, current: ShrincsPublicKey): void {
    const next = statefulTreeId(nextStatefulPublicKey);
    if (next === statefulTreeId(current.statefulPublicKey)) {
      throw new StatefulTreeSpentError(next);
    }
  }

  /// Pre-flight for full-bundle installs (`recoverWallet` / `transferOwnership`
  /// / `setErc1271Key` / `upgradeToAndCall` migrate): both halves of `nextKey`
  /// must differ from the installed main bundle.
  /// Pre-flight mirror of what `migrate` spends: all four trees of the payload
  /// (main + ERC-1271, stateful + stateless). The client can see the installed
  /// main bundle and the installed 1271 commitment, so it checks both payload
  /// bundles against the main bundle, the 1271 bundle against the installed
  /// 1271 commitment, and the two payload bundles against each other — the
  /// wallet installs main first, so a shared tree trips on the 1271 install.
  private assertFreshMigration(
    migratorPayload: Hex,
    current: ShrincsPublicKey,
    state: ShrincsWalletState
  ): void {
    const { mainBundle, erc1271Bundle } = decodeInitPayload(migratorPayload);
    this.assertFreshBundle(mainBundle, current);
    this.assertFreshBundle(erc1271Bundle, current);
    if (
      erc1271Bundle.publicKeyCommitment.toLowerCase() ===
      state.erc1271PublicKeyCommitment.toLowerCase()
    ) {
      throw new StatefulTreeSpentError(
        statefulTreeId(erc1271Bundle.statefulPublicKey)
      );
    }
    this.assertFreshBundle(erc1271Bundle, mainBundle);
  }

  private assertFreshBundle(nextKey: ShrincsPublicKey, current: ShrincsPublicKey): void {
    this.assertFreshStatefulTree(nextKey.statefulPublicKey, current);
    const next = statelessTreeId(nextKey.pkSeed, nextKey.hypertreeRoot);
    if (next === statelessTreeId(current.pkSeed, current.hypertreeRoot)) {
      throw new StatelessTreeSpentError(next);
    }
  }

  /// Common stateful-op preamble: assert provider, read state, recover key, pick
  /// the lowest unused leaf (or honor an explicit override). `excludeLeaves`
  /// constrains only the automatic pick; callers with an explicit `keyOpts.leaf`
  /// are responsible for their own exclusion guard (see `markLeavesUsed`).
  private async prepareStatefulOp(
    keyOpts?: ShrincsTxKeyOptions,
    excludeLeaves?: ReadonlySet<number>,
    preflight?: (
      keypair: ShrincsKeyPair,
      state: ShrincsWalletState
    ) => void | Promise<void>
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
    // Caller pre-flights (e.g. spent-tree checks) run BEFORE any leaf is
    // reserved: reservations have no release API, so a rejected call must not
    // burn a signing leaf.
    await preflight?.(keypair, state);
    // Validate the excluded leaves BEFORE reserving. `excludeLeaves` carries the
    // revocation targets (`markLeavesUsed`), which must be valid signing leaves
    // `[1..maxSignatures]`. Rejecting a malformed target here — before any leaf
    // is reserved or signed — means a rejected call never burns a one-time
    // signing leaf.
    if (excludeLeaves) {
      for (const target of excludeLeaves) {
        if (
          !Number.isInteger(target) ||
          target < 1 ||
          target > state.maxSignatures
        ) {
          throw new LeafOutOfRangeError(target, state.maxSignatures);
        }
      }
    }
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

  private buildContractCall(
    functionName: string,
    args: readonly unknown[],
    value: bigint,
    abi: readonly unknown[] = shrincsWalletAbi as readonly unknown[]
  ): ContractCallParams {
    return {
      address: this.walletAddress,
      abi,
      functionName,
      args,
      value,
      account: this.account as Account | Address,
    };
  }

  private async submit(
    functionName: string,
    args: readonly unknown[],
    value: bigint,
    opts: TxOptions,
    abi?: readonly unknown[]
  ): Promise<TransactionReceipt> {
    return this.send(
      this.buildContractCall(functionName, args, value, abi),
      value,
      opts
    );
  }

  private async send(
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
    params: ExecuteParams,
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const { contractCall, totalValue } = await this.buildExecuteCall(
      params,
      opts
    );
    return this.send(contractCall, totalValue, opts);
  }

  /// Sign an `execute` once, price it, and hand back a `send()` that broadcasts
  /// those exact bytes. This is the quote-then-send path.
  ///
  /// Why not a separate estimate call: a stateful leaf may sign ONE message.
  /// Quoting by signing, then signing again at send time — with any change to
  /// the params — would put two different messages under one leaf, which is
  /// forgeable. Here there is exactly one signature; the estimate is computed
  /// over it and `send()` reuses it unchanged, so nothing is ever re-signed.
  ///
  /// The reservation is per client instance and has no release: a prepared op
  /// that is never sent leaves its leaf unused on-chain (the bitmap is
  /// authoritative) but not re-issued by this client, so a later prepare in the
  /// same process cannot sign a second message at it.
  async prepareExecute(
    params: ExecuteParams,
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<PreparedExecute> {
    const { contractCall, totalValue, executeFee, maxFee, leaf } =
      await this.buildExecuteCall(params, opts);
    const cost = await estimateTxCost({
      publicClient: this.publicClient,
      account: this.account,
      contractCall,
      totalValue,
      opts,
    });
    let sent = false;
    return {
      leaf,
      maxFee,
      executeFee,
      totalValue,
      estimate: { ...cost, executeFee },
      send: () => {
        if (sent) {
          return Promise.reject(
            new Error("prepared execute already sent: prepare a new one")
          );
        }
        sent = true;
        return this.send(contractCall, totalValue, opts);
      },
    };
  }

  private async buildExecuteCall(
    params: ExecuteParams,
    opts: TxOptions & ShrincsTxKeyOptions
  ): Promise<{
    contractCall: ContractCallParams;
    totalValue: bigint;
    executeFee: bigint;
    maxFee: bigint;
    leaf: number;
  }> {
    const value = params.value ?? 0n;
    const data = params.data ?? "0x";
    // A call with calldata to a codeless target is a phantom no-op that still
    // consumes a leaf (solady's `execute` has no `extcodesize` guard). Pure
    // value transfers (empty calldata) to an EOA are legitimate, so guard only
    // when calldata is present.
    if (data !== "0x") {
      await this.assertExecuteTargetHasCode(params.target);
    }
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts);
    const maxFee = params.maxFee ?? state.executeFee;
    const ctx = buildActionContext({
      domainSeparator: ds,
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
      actionType: ACTION_EXECUTE,
      payloadHash: executePayloadHash(
        params.target,
        value,
        keccakData(data),
        maxFee
      ),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    // msg.value funds the ceiling; any excess over the live fee stays in the
    // wallet (the user's own funds), and the call cannot underfund a fee move
    // within the cap.
    return {
      contractCall: this.buildContractCall(
        "execute",
        [
          publicKeyToAbi(keypair.publicKey),
          signature,
          params.target,
          value,
          data,
          maxFee,
        ],
        value + maxFee
      ),
      totalValue: value + maxFee,
      executeFee: state.executeFee,
      maxFee,
      leaf,
    };
  }

  /// Assert an `execute` target holds code, throwing `ExecuteTargetHasNoCodeError`
  /// if it does not. The direct `execute` path calls this automatically for
  /// calls that carry calldata; callers that assemble a userOp through
  /// `buildExecuteUserOp` / `buildExecuteBatchUserOp` should call it themselves
  /// before signing, since a call to a codeless target still consumes a leaf.
  async assertExecuteTargetHasCode(target: Address): Promise<void> {
    const code = await this.publicClient.getCode({ address: target });
    if (code === undefined || code === "0x") {
      throw new ExecuteTargetHasNoCodeError(target);
    }
  }

  /// Withdraw from the wallet's EntryPoint deposit.
  async withdrawDepositTo(
    params: { to: Address; amount: bigint },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const {
      keypair,
      state,
      leaf,
      domainSeparator: ds,
    } = await this.prepareStatefulOp(opts);
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

  /// Rotate the dedicated ERC-1271 verifier key (authorized by a stateful
  /// signature from the main key). The new key travels as a FULL bundle: the
  /// wallet derives its commitment on-chain and spends both of its trees in
  /// the lifetime registries, so the bundle must be entirely fresh — never
  /// held by this wallet under either role. Pre-flights the collisions the
  /// client can see (the installed main bundle's trees, and re-installing the
  /// installed 1271 bundle); older trees are only caught on-chain
  /// (`StatefulTreeSpentError` / `StatelessTreeSpentError` decoded). A
  /// rejected bundle consumes no leaf: the wallet installs before verifying,
  /// and the client pre-flights before reserving.
  async setErc1271Key(
    params: { newErc1271Key: ShrincsPublicKey; newHashSuite?: number },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    // beta.2 took a bare `bytes32` commitment (pre tree-isolation); this SDK only
    // offers the full-bundle form. Reject loudly rather than send a wrong-ABI tx
    // — the wallet should be upgraded first.
    const version = await this.resolveVersion();
    if (version.quirks.erc1271KeyArgument !== "publicKeyBundle") {
      throw new UnsupportedByWalletVersionError(version.label, "setErc1271Key");
    }
    const hashSuite = params.newHashSuite ?? HASH_SUITE_KECCAK_256;
    const {
      keypair,
      state,
      leaf,
      domainSeparator: ds,
    } = await this.prepareStatefulOp(opts, undefined, (kp, st) => {
      this.assertFreshBundle(params.newErc1271Key, kp.publicKey);
      // Re-installing the CURRENT 1271 bundle: equal commitments mean equal
      // bundles, and the wallet refuses its stateful half first.
      if (
        params.newErc1271Key.publicKeyCommitment.toLowerCase() ===
        st.erc1271PublicKeyCommitment.toLowerCase()
      ) {
        throw new StatefulTreeSpentError(
          statefulTreeId(params.newErc1271Key.statefulPublicKey)
        );
      }
    });
    const ctx = buildActionContext({
      domainSeparator: ds,
      nonce: state.actionNonce,
      keyVersion: state.keyVersion,
      actionType: ACTION_SET_ERC1271_KEY,
      payloadHash: setErc1271KeyPayloadHash(
        params.newErc1271Key.publicKeyCommitment,
        hashSuite
      ),
    });
    const signature = keypair.signStatefulActionAt(ctx, leaf);
    return this.submit(
      "setErc1271Key",
      [
        publicKeyToAbi(keypair.publicKey),
        signature,
        publicKeyToAbi(params.newErc1271Key),
        hashSuite,
      ],
      0n,
      opts
    );
  }

  /// Routine stateful rotation: refresh the stateful subkey, reuse the stateless
  /// recovery root. `nextStatefulPublicKey` is the fresh stateful key's encoded
  /// 68-byte public key (from a freshly keygen'd bundle under a new commitment).
  /// Pre-flights `StatefulTreeSpentError` when it is the installed tree (any
  /// budget); older trees are refused on-chain — trees never come back.
  async rotateKey(
    params: { nextStatefulPublicKey: Hex },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const {
      keypair,
      state,
      leaf,
      domainSeparator: ds,
    } = await this.prepareStatefulOp(opts, undefined, (kp) =>
      this.assertFreshStatefulTree(params.nextStatefulPublicKey, kp.publicKey)
    );
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
    // `prepareStatefulOp` validates the target leaves (its `excludeLeaves`) and
    // reserves the authorizing leaf only after they pass, so a malformed target
    // never burns a signing leaf. All guards run BEFORE signing.
    const { keypair, state, leaf, domainSeparator: ds } =
      await this.prepareStatefulOp(opts, targetSet);
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

  /// UUPS upgrade gated by a stateful signature. Works against BOTH the deployed
  /// V1.0.1-beta.2 generation and later ones: the SDK always emits the 6-field
  /// blob (auth signature + a `verifyUpgrade` probe vector for the target). The
  /// beta.2 caller reads the first 5 fields and forwards the whole blob to the
  /// target's probe; later callers read all 6. Set `preflight: false` to skip
  /// the staticcall probe pre-check (on by default).
  async upgradeToAndCall(
    params: {
      newImplementation: Address;
      shouldMigrate?: boolean;
      migratorPayload?: Hex;
      preflight?: boolean;
    },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    const shouldMigrate = params.shouldMigrate ?? false;
    const migratorPayload = params.migratorPayload ?? "0x";
    // The probe vector binds ONLY the target address, so it can be built before
    // reserving the wallet's signing leaf.
    const probePayload = this.buildUpgradeProbeVector(params.newImplementation);
    const {
      keypair,
      state,
      leaf,
      domainSeparator: ds,
    } = await this.prepareStatefulOp(
      opts,
      undefined,
      shouldMigrate
        ? (kp, st) => this.assertFreshMigration(migratorPayload, kp.publicKey, st)
        : undefined
    );
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
      probePayload,
    });
    if (params.preflight !== false) {
      await this.verifyUpgrade(params.newImplementation, data);
    }
    const receipt = await this.submit(
      "upgradeToAndCall",
      [params.newImplementation, data],
      0n,
      opts
    );
    // The wallet's implementation just changed, so any memoized version is
    // stale — the next resolveVersion()/getWalletState() must re-read the slot.
    this.walletVersion = undefined;
    return receipt;
  }

  /*  ── dual-signature & stateless writes ───────────────────────────────  */

  /// Atomic ownership handover: a fresh bundle (`nextKey`) plus a new classical
  /// owner, authorized by BOTH a stateful owner-binding signature and a stateless
  /// recovery signature from the current key — AND, on wallets past beta.2, the
  /// RECIPIENT's hybrid acceptance (`OwnershipAcceptance`, produced by
  /// `signOwnershipAcceptance` on their side): `newOwner`'s signature and a
  /// stateful signature from `nextKey` itself, each over the handover payload.
  /// Without it a mistyped `newOwner` or an unusable bundle would strand the
  /// wallet behind an owner that does not exist, every path (recovery
  /// included) gated behind it.
  ///
  /// Both acceptance halves are verified locally BEFORE any current-key leaf is
  /// reserved or signature produced, so a bad acceptance costs nothing. On a
  /// beta.2 wallet (`handoverAcceptance: "none"`) the legacy single-step call
  /// is sent and any acceptance supplied is ignored.
  async transferOwnership(
    params: {
      nextKey: ShrincsPublicKey;
      newOwner: Address;
      keyAcceptance?: StatefulSignature;
      ownerAcceptance?: Hex;
    },
    opts: TxOptions & ShrincsTxKeyOptions = {}
  ): Promise<TransactionReceipt> {
    if (params.newOwner === ZERO_ADDRESS) throw new ZeroAddressOwnerError();
    const version = await this.resolveVersion();
    const hybrid = version.quirks.handoverAcceptance === "hybrid";
    const {
      keypair,
      state,
      leaf,
      domainSeparator: ds,
    } = await this.prepareStatefulOp(opts, undefined, async (kp) => {
      this.assertFreshBundle(params.nextKey, kp.publicKey);
      if (hybrid) await this.assertOwnershipAcceptance(params, kp);
    });
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

    const legacyArgs = [
      publicKeyToAbi(keypair.publicKey),
      ownerBindingSignature,
      recoverySignature,
      publicKeyToAbi(params.nextKey),
      params.newOwner,
    ] as const;
    if (!hybrid) {
      return this.submit("transferOwnership", legacyArgs, 0n, opts, version.abi);
    }
    return this.submit(
      "transferOwnership",
      [...legacyArgs, params.keyAcceptance, params.ownerAcceptance],
      0n,
      opts
    );
  }

  /// Local mirror of `ShrincsWallet._verifyOwnershipAcceptance`, run in the
  /// pre-flight so a bad acceptance is rejected before the current owner
  /// reserves a leaf or produces either of their signatures. The classical
  /// half recovers the EIP-712 signer (an EOA) and falls back to the node's
  /// ERC-1271-aware `verifyTypedData` for a contract `newOwner`; the PQ half
  /// is verified through the wasm against the INCOMING commitment.
  private async assertOwnershipAcceptance(
    params: {
      nextKey: ShrincsPublicKey;
      newOwner: Address;
      keyAcceptance?: StatefulSignature;
      ownerAcceptance?: Hex;
    },
    keypair: ShrincsKeyPair
  ): Promise<void> {
    if (params.ownerAcceptance === undefined) {
      throw new InvalidOwnerAcceptanceError(
        "no ownerAcceptance supplied (the recipient signs it via signOwnershipAcceptance)"
      );
    }
    if (params.keyAcceptance === undefined) {
      throw new InvalidKeyAcceptanceError(
        "no keyAcceptance supplied (the recipient signs it via signOwnershipAcceptance)"
      );
    }
    const nextCommitment = params.nextKey.publicKeyCommitment;
    const payloadHash = transferOwnershipPayloadHash(params.newOwner, nextCommitment);

    // Classical half.
    const typedData = quipSignedHashTypedData(payloadHash, this.chainId, this.walletAddress);
    let ownerOk = false;
    try {
      const recovered = await recoverTypedDataAddress({
        ...typedData,
        signature: params.ownerAcceptance,
      });
      ownerOk = recovered.toLowerCase() === params.newOwner.toLowerCase();
    } catch {
      ownerOk = false;
    }
    if (!ownerOk) {
      const code = await this.publicClient.getCode({ address: params.newOwner });
      if (code && code !== "0x") {
        ownerOk = await this.publicClient.verifyTypedData({
          address: params.newOwner,
          ...typedData,
          signature: params.ownerAcceptance,
        });
      }
    }
    if (!ownerOk) {
      throw new InvalidOwnerAcceptanceError(
        `signature does not verify for newOwner ${params.newOwner}`
      );
    }

    // PQ half: leaf range against the INCOMING key's budget, then the wasm verify.
    const acceptLeaf = params.keyAcceptance.authPath.length;
    const nextBudget = statefulMaxSignatures(params.nextKey.statefulPublicKey);
    if (acceptLeaf < 1 || acceptLeaf > nextBudget) {
      throw new InvalidKeyAcceptanceError(
        `acceptance leaf ${acceptLeaf} outside [1, ${nextBudget}]`
      );
    }
    const ctx = buildOwnershipAcceptanceContext({
      domainSeparator: domainSeparator(this.chainId, this.walletAddress),
      newOwner: params.newOwner,
      nextCommitment,
    });
    const message = statefulRawMessageHash(
      nextCommitment,
      statefulActionMessageHash(nextCommitment, ctx)
    );
    if (!keypair.verifyStatefulEnvelope(params.nextKey, message, params.keyAcceptance)) {
      throw new InvalidKeyAcceptanceError(
        "stateful signature does not verify against the incoming bundle"
      );
    }
  }

  /// Break-glass recovery: install an entirely fresh bundle authorized by the
  /// stateless recovery signature. Ownership unchanged. No leaf consumed.
  /// Both halves of `nextKey` must be fresh: the installed trees pre-flight
  /// `StatefulTreeSpentError` / `StatelessTreeSpentError`; older ones on-chain.
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
    this.assertFreshBundle(params.nextKey, keypair.publicKey);
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
  /// installed `erc1271PublicKeyCommitment`). The `owner` must sign for the wallet's
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
      state.erc1271PublicKeyCommitment.toLowerCase()
    ) {
      throw new CommitmentMismatchError(
        params.erc1271KeyPair.publicKeyCommitment,
        state.erc1271PublicKeyCommitment
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
      args: [
        params.target,
        params.value ?? 0n,
        params.data ?? "0x",
        params.maxFee,
      ],
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
