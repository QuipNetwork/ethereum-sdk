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
  type PublicClient,
  type TransactionReceipt,
  type WalletClient,
} from "viem";

import { assertProviderState, boundChain } from "../internal/providerState.js";
import { tryMulticall } from "../internal/multicall.js";
import { shrincsPaymasterAbi } from "./abi/ShrincsPaymaster.js";
import { assertHdIndex } from "./hd.js";
import {
  EmptyLeavesError,
  StatefulBudgetExhaustedError,
  StatefulTreeSpentError,
  VerifierMismatchError,
} from "./errors.js";
import {
  LeafReservationStore,
  reserveExplicitLeaf,
  reserveSelectedLeaf,
} from "./leafReservation.js";
import {
  buildStatefulRotationTarget,
  statefulTreeId,
  publicKeyToAbi,
} from "./shrincsCodec.js";
import { prepareTx, type TxOptions } from "./gas.js";
import { assertReceiptSuccess } from "./internal/assertReceiptSuccess.js";
import {
  type BitmapWordReader,
  findLowestUnusedLeaf,
  wordsFromResults,
} from "./internal/leafBitmap.js";
import { LeafScanFrontier } from "./internal/leafFrontier.js";
import { withDecodedError } from "./internal/decodeError.js";
import { type ShrincsKeyPair, type ShrincsSigner } from "./shrincsSigner.js";
import {
  type PackedUserOperation,
  signPaymasterUserOp,
} from "./userOp.js";
import {
  DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
  DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
} from "./constants.js";

export interface ShrincsVerifierState {
  commitment: Hex;
  hashSuite: number;
  keyVersion: bigint;
  maxSignatures: number;
  statefulLeavesUsed: number;
}

export interface ShrincsPaymasterClientParams {
  paymasterAddress: Address;
  publicClient: PublicClient;
  walletClient: WalletClient;
  /// Operator signer holding the sponsorship verifier key.
  signer: ShrincsSigner;
  commitment: Hex;
  /// Caller-chosen key-derivation index. Required when recovering a keypair
  /// from `signer` (no injected `keypair`). Unused when `keypair` is provided.
  derivationIndex?: number;
  chainId: number;
  account: Address;
  /// Pre-built keypair override. Takes precedence over `signer.recoverKeyPair`
  /// — REQUIRED after a `rotateStatefulKey`, where the live bundle is a graft
  /// of the new stateful index and the ORIGINAL stateless index (build it with
  /// `signer.deriveKeyPair({ statefulIndex, statelessIndex, maxSignatures })`;
  /// a plain `recoverKeyPair` on either index reproduces the wrong commitment).
  keypair?: ShrincsKeyPair;
}

/// Per-paymaster client: sponsorship signing + verifier/deposit/stake admin.
/// Independent of the wallet client — the wallet produces an unsigned userOp,
/// the paymaster fills `paymasterAndData`.
export class ShrincsPaymasterClient {
  readonly paymasterAddress: Address;
  readonly chainId: number;
  readonly account: Address;
  readonly commitment: Hex;
  readonly derivationIndex?: number;

  private readonly publicClient: PublicClient;
  private readonly walletClient: WalletClient;
  private readonly signer: ShrincsSigner;
  private readonly keypair?: ShrincsKeyPair;
  /// Per-instance record of sponsorship leaves already handed out for signing,
  /// so concurrent `sponsorUserOp` calls cannot race to the same lowest-unused
  /// leaf and sign two messages at one one-time leaf.
  private readonly leafReservations = new LeafReservationStore();
  /// Per-epoch memory of how far the bitmap is consumed, so a scan skips the
  /// exhausted prefix instead of re-reading it on every sponsorship.
  private readonly leafFrontier = new LeafScanFrontier();

  constructor(params: ShrincsPaymasterClientParams) {
    this.paymasterAddress = params.paymasterAddress;
    this.publicClient = params.publicClient;
    this.walletClient = params.walletClient;
    this.signer = params.signer;
    this.commitment = params.commitment;
    if (params.derivationIndex !== undefined) {
      assertHdIndex(params.derivationIndex, "derivationIndex");
    }
    this.derivationIndex = params.derivationIndex;
    this.chainId = params.chainId;
    this.account = params.account;
    this.keypair = params.keypair;
  }

  /// The operator keypair: the explicit override when set (post-rotation
  /// grafted bundles), else re-derived from the signer's derivation index.
  private operatorKeyPair(maxSignatures: number): ShrincsKeyPair {
    if (this.keypair) return this.keypair;
    if (this.derivationIndex === undefined) {
      throw new Error(
        "ShrincsPaymasterClient has no derivationIndex to recover a keypair with"
      );
    }
    return this.signer.recoverKeyPair(this.derivationIndex, { maxSignatures });
  }

  /*  ── reads ───────────────────────────────────────────────────────────  */

  async getShrincsVerifier(): Promise<ShrincsVerifierState> {
    const [commitment, hashSuite, keyVersion, maxSignatures, statefulLeavesUsed] =
      (await withDecodedError(
        this.publicClient.readContract({
          address: this.paymasterAddress,
          abi: shrincsPaymasterAbi,
          functionName: "getShrincsVerifier",
        })
      )) as [Hex, number, bigint, number, number];
    return {
      commitment,
      hashSuite: Number(hashSuite),
      keyVersion: BigInt(keyVersion),
      maxSignatures: Number(maxSignatures),
      statefulLeavesUsed: Number(statefulLeavesUsed),
    };
  }

  async getDeposit(): Promise<bigint> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.paymasterAddress,
        abi: shrincsPaymasterAbi,
        functionName: "getDeposit",
      })
    ) as Promise<bigint>;
  }

  async isStatefulLeafUsed(leaf: number): Promise<boolean> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.paymasterAddress,
        abi: shrincsPaymasterAbi,
        functionName: "isStatefulLeafUsed",
        args: [BigInt(leaf)],
      })
    ) as Promise<boolean>;
  }

  /// Reads `count` consecutive bitmap words from `startWord` in one multicall.
  /// Throws `LeafBitmapReadError` if any word cannot be read: an unread word
  /// leaves the used state of its 256 leaves unknown, and signing at a leaf
  /// that is not confirmed free risks one-time-signature reuse.
  private readonly readBitmapWords: BitmapWordReader = async (startWord, count) => {
    const calls = [];
    for (let offset = 0; offset < count; offset++) {
      calls.push({
        address: this.paymasterAddress,
        abi: shrincsPaymasterAbi,
        functionName: "statefulLeafBitmapWord" as const,
        args: [BigInt(startWord + offset)] as const,
      });
    }
    const results = await tryMulticall(this.publicClient, calls);
    return wordsFromResults(results, startWord);
  };

  /// Lowest sponsorship leaf the on-chain bitmap reports as free and `skip`
  /// accepts, or `undefined` when the epoch offers none. Resumes from the
  /// cached frontier and stops at the first word holding a usable leaf, so the
  /// cost does not grow with `maxSignatures`.
  private async scanLowestUnusedLeaf(
    verifier: ShrincsVerifierState,
    skip?: (leaf: number) => boolean
  ): Promise<number | undefined> {
    const epoch = {
      commitment: verifier.commitment,
      keyVersion: verifier.keyVersion,
    };
    const { leaf, frontierWord } = await findLowestUnusedLeaf({
      maxSignatures: verifier.maxSignatures,
      readWords: this.readBitmapWords,
      startWord: this.leafFrontier.startWord(epoch),
      skip,
    });
    this.leafFrontier.advance(epoch, frontierWord);
    return leaf;
  }

  /// Lowest unused sponsorship leaf in `1..maxSignatures` for the current
  /// verifier epoch. Reads the bitmap by word (shared with the wallet client).
  async lowestUnusedLeaf(verifier: ShrincsVerifierState): Promise<number> {
    if (verifier.statefulLeavesUsed >= verifier.maxSignatures) {
      throw new StatefulBudgetExhaustedError(
        verifier.maxSignatures,
        verifier.statefulLeavesUsed
      );
    }
    const leaf = await this.scanLowestUnusedLeaf(verifier);
    if (leaf === undefined) {
      throw new StatefulBudgetExhaustedError(
        verifier.maxSignatures,
        verifier.statefulLeavesUsed
      );
    }
    return leaf;
  }

  /*  ── sponsorship ─────────────────────────────────────────────────────  */

  /// Fill `paymasterAndData` for a sponsored userOp. Reads the on-chain verifier,
  /// pre-checks the operator key's commitment matches it (throwing
  /// `VerifierMismatchError` BEFORE signing), picks the lowest unused leaf, and
  /// signs the sponsorship binding.
  async sponsorUserOp(params: {
    userOp: PackedUserOperation;
    validUntil?: number;
    validAfter?: number;
    verificationGasLimit?: bigint;
    postOpGasLimit?: bigint;
    leaf?: number;
  }): Promise<{ paymasterAndData: Hex; leaf: number }> {
    await assertProviderState({
      publicClient: this.publicClient,
      expectedChainId: this.chainId,
    });
    const verifier = await this.getShrincsVerifier();
    const keypair = this.operatorKeyPair(verifier.maxSignatures);
    if (
      keypair.publicKeyCommitment.toLowerCase() !== verifier.commitment.toLowerCase()
    ) {
      throw new VerifierMismatchError(keypair.publicKeyCommitment, verifier.commitment);
    }
    // Reserve the leaf in-process before signing so concurrent sponsorships (or
    // a sign-then-retry) cannot both pick the same lowest-unused leaf and sign
    // two messages at one one-time leaf. An explicit override is reserved too.
    const reservationKey = {
      commitment: verifier.commitment,
      keyVersion: verifier.keyVersion,
    };
    let leaf: number;
    if (params.leaf !== undefined) {
      leaf = params.leaf;
      await reserveExplicitLeaf(this.leafReservations, reservationKey, leaf);
    } else {
      if (verifier.statefulLeavesUsed >= verifier.maxSignatures) {
        throw new StatefulBudgetExhaustedError(
          verifier.maxSignatures,
          verifier.statefulLeavesUsed
        );
      }
      leaf = await reserveSelectedLeaf(
        this.leafReservations,
        reservationKey,
        (isReserved) => this.scanLowestUnusedLeaf(verifier, isReserved),
        verifier.maxSignatures,
        verifier.statefulLeavesUsed
      );
    }
    const paymasterAndData = signPaymasterUserOp({
      keypair,
      userOp: params.userOp,
      paymaster: this.paymasterAddress,
      chainId: BigInt(this.chainId),
      keyVersion: verifier.keyVersion,
      verificationGasLimit: params.verificationGasLimit,
      postOpGasLimit: params.postOpGasLimit,
      validUntil: params.validUntil,
      validAfter: params.validAfter,
      leaf,
    });
    return { paymasterAndData, leaf };
  }

  /// Local (no-RPC) upper bound on the gas a sponsored userOp can cost the
  /// paymaster: (verification + postOp gas limits) × maxFeePerGas, plus the
  /// wallet-side limits. Callers size deposits / per-op policy against this.
  estimateSponsorshipCost(params: {
    maxFeePerGas: bigint;
    verificationGasLimit?: bigint;
    postOpGasLimit?: bigint;
  }): bigint {
    const ver = params.verificationGasLimit ?? DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT;
    const post = params.postOpGasLimit ?? DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT;
    return (ver + post) * params.maxFeePerGas;
  }

  /*  ── admin writes ────────────────────────────────────────────────────  */

  /// Rotate ONLY the stateful subkey of the global sponsorship verifier key
  /// (owner-only FIAT rotation — no PQ signature of its own; the owner is
  /// expected to be a post-quantum wallet). Bumps the epoch and resets the
  /// leaf bitmap; the current bundle's stateless half is reused, never rotated
  /// (it is inert — the paymaster only verifies stateful sponsorship
  /// signatures). `nextStatefulPublicKey` is the fresh stateful key's encoded
  /// 68-byte public key (from a freshly keygen'd bundle under a new commitment);
  /// the new `maxSignatures` budget is decoded on-chain from that encoding.
  /// The operator signer must still hold the CURRENT key: its public bundle is
  /// pinned on-chain to authorize carrying the stateless half forward
  /// (`VerifierMismatchError` is thrown before submitting if it drifted).
  async rotateStatefulKey(
    params: { nextStatefulPublicKey: Hex },
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const verifier = await this.getShrincsVerifier();
    const keypair = this.operatorKeyPair(verifier.maxSignatures);
    if (
      keypair.publicKeyCommitment.toLowerCase() !== verifier.commitment.toLowerCase()
    ) {
      throw new VerifierMismatchError(keypair.publicKeyCommitment, verifier.commitment);
    }
    // Trees never come back: refuse the installed tree (any budget) before
    // sending; older trees are refused on-chain (`StatefulTreeSpentError`).
    const nextTree = statefulTreeId(params.nextStatefulPublicKey);
    if (nextTree === statefulTreeId(keypair.publicKey.statefulPublicKey)) {
      throw new StatefulTreeSpentError(nextTree);
    }
    const nextStatefulKey = buildStatefulRotationTarget({
      nextStatefulPublicKey: params.nextStatefulPublicKey,
      currentPkSeed: keypair.publicKey.pkSeed,
      currentHypertreeRoot: keypair.publicKey.hypertreeRoot,
    });
    return this.submit(
      "rotateStatefulKey",
      [
        publicKeyToAbi(keypair.publicKey),
        {
          statefulPublicKey: nextStatefulKey.statefulPublicKey,
          publicKeyCommitment: nextStatefulKey.publicKeyCommitment,
        },
      ],
      0n,
      opts
    );
  }

  /// Revoke outstanding sponsorship leaves in the current epoch (owner-only
  /// fiat, mirroring the contract's idempotent batch semantics: already-used
  /// targets are skipped on-chain, out-of-range ones revert the whole batch).
  /// Every freshly revoked leaf decrements `remainingStatefulSignatures()` —
  /// revocation spends budget exactly like a landed sponsorship.
  async markLeavesUsed(
    leaves: readonly number[],
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    // Fail fast client-side (mirrors the contract's EmptyLeaves revert).
    if (leaves.length === 0) throw new EmptyLeavesError();
    return this.submit("markLeavesUsed", [leaves], 0n, opts);
  }

  async deposit(value: bigint, opts: TxOptions = {}): Promise<TransactionReceipt> {
    return this.submit("deposit", [], value, opts);
  }

  async withdrawTo(
    params: { to: Address; amount: bigint },
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    return this.submit("withdrawTo", [params.to, params.amount], 0n, opts);
  }

  async addStake(
    params: { unstakeDelaySec: number; value: bigint },
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    return this.submit("addStake", [params.unstakeDelaySec], params.value, opts);
  }

  async unlockStake(opts: TxOptions = {}): Promise<TransactionReceipt> {
    return this.submit("unlockStake", [], 0n, opts);
  }

  async withdrawStake(to: Address, opts: TxOptions = {}): Promise<TransactionReceipt> {
    return this.submit("withdrawStake", [to], 0n, opts);
  }

  private async submit(
    functionName: string,
    args: readonly unknown[],
    value: bigint,
    opts: TxOptions
  ): Promise<TransactionReceipt> {
    await assertProviderState({
      publicClient: this.publicClient,
      expectedChainId: this.chainId,
      walletClient: this.walletClient,
      expectedAccount: this.account,
    });
    const contractCall = {
      address: this.paymasterAddress,
      abi: shrincsPaymasterAbi as readonly unknown[],
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
}
