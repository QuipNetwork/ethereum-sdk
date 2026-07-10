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
import { shrincsPaymasterAbi } from "./abi/ShrincsPaymaster.js";
import { HASH_SUITE_KECCAK_256 } from "./constants.js";
import { StatefulBudgetExhaustedError, VerifierMismatchError } from "./errors.js";
import { prepareTx, type TxOptions } from "./gas.js";
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
  vaultId: Hex;
  chainId: number;
  account: Address;
}

/// Per-paymaster client: sponsorship signing + verifier/deposit/stake admin.
/// Independent of the wallet client — the wallet produces an unsigned userOp,
/// the paymaster fills `paymasterAndData`.
export class ShrincsPaymasterClient {
  readonly paymasterAddress: Address;
  readonly chainId: number;
  readonly account: Address;
  readonly vaultId: Hex;

  private readonly publicClient: PublicClient;
  private readonly walletClient: WalletClient;
  private readonly signer: ShrincsSigner;

  constructor(params: ShrincsPaymasterClientParams) {
    this.paymasterAddress = params.paymasterAddress;
    this.publicClient = params.publicClient;
    this.walletClient = params.walletClient;
    this.signer = params.signer;
    this.vaultId = params.vaultId;
    this.chainId = params.chainId;
    this.account = params.account;
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

  /// Lowest unused sponsorship leaf in `1..maxSignatures` for the current
  /// verifier epoch. Sequential reads (the paymaster has no packed getter).
  async lowestUnusedLeaf(verifier: ShrincsVerifierState): Promise<number> {
    if (verifier.statefulLeavesUsed >= verifier.maxSignatures) {
      throw new StatefulBudgetExhaustedError(
        verifier.maxSignatures,
        verifier.statefulLeavesUsed
      );
    }
    for (let leaf = 1; leaf <= verifier.maxSignatures; leaf++) {
      if (!(await this.isStatefulLeafUsed(leaf))) return leaf;
    }
    throw new StatefulBudgetExhaustedError(
      verifier.maxSignatures,
      verifier.statefulLeavesUsed
    );
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
    const keypair: ShrincsKeyPair = this.signer.recoverKeyPair(this.vaultId, {
      maxSignatures: verifier.maxSignatures,
    });
    if (
      keypair.publicKeyCommitment.toLowerCase() !== verifier.commitment.toLowerCase()
    ) {
      throw new VerifierMismatchError(keypair.publicKeyCommitment, verifier.commitment);
    }
    const leaf = params.leaf ?? (await this.lowestUnusedLeaf(verifier));
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

  /// Rotate the global sponsorship verifier key (owner-only; bumps the epoch).
  async setShrincsVerifier(
    params: { commitment: Hex; hashSuite?: number; maxSignatures: number },
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    return this.submit(
      "setShrincsVerifier",
      [
        params.commitment,
        params.hashSuite ?? HASH_SUITE_KECCAK_256,
        params.maxSignatures,
      ],
      0n,
      opts
    );
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
    return this.publicClient.waitForTransactionReceipt({ hash });
  }
}
