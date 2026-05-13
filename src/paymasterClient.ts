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
} from "viem";

import { quipPaymasterAbi } from "./abi/QuipPaymaster.js";
import { QuipSigner } from "./signer.js";
import { withDecodedError } from "./internal/decodeError.js";
import {
  type TxOptions,
  type PreparedTx,
  type ContractCallParams,
  prepareTx,
} from "./gas.js";
import { buildSignedPaymasterAndData } from "./userOp.js";
import {
  type PackedUserOperation,
  type WinternitzAddress,
} from "./wotsCodec.js";

/// Client for the per-wallet WOTS+ paymaster. Wraps the paymaster
/// contract's view + admin functions and exposes a `sponsorUserOp`
/// helper that produces the `paymasterAndData` field for a sponsored
/// UserOp.
///
/// Roles:
///   - **owner**: the paymaster operator. Can set/remove per-wallet
///     verifiers, deposit, withdraw, stake/unstake. Most write methods
///     check this on chain.
///   - **operator signer**: a `QuipSigner` whose `quantumSecret` controls
///     the per-wallet WOTS+ verifier keys. Used by `sponsorUserOp` to
///     sign sponsorship attestations. This is separate from a user's
///     wallet signer — the verifier chain is the paymaster's, not the
///     user's.
///   - **anyone**: can call `deposit(value)` to top up the paymaster's
///     EntryPoint balance.
///
/// All write methods accept `TxOptions` (simulate-before-send by
/// default, configurable gas buffer, full fee/nonce pass-through). All
/// reverts route through `decodeContractError` → typed `QuipError`
/// subclasses (e.g. `ZeroValuePqVerifierKeyError`,
/// `PqVerifierNotRegisteredError`, `VerifierKeyInUseError`).
export class QuipPaymasterClient {
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private paymasterAddress: Address;
  private account: Address;
  private chainId: number;

  constructor(params: {
    paymasterAddress: Address;
    publicClient: PublicClient;
    walletClient: WalletClient;
    account: Address;
    chainId: number;
  }) {
    this.paymasterAddress = params.paymasterAddress;
    this.publicClient = params.publicClient;
    this.walletClient = params.walletClient;
    this.account = params.account;
    this.chainId = params.chainId;
  }

  getAddress(): Address {
    return this.paymasterAddress;
  }

  /// Paymaster's ETH balance held at the EntryPoint. Sponsored UserOps
  /// are charged against this deposit.
  async getDeposit(): Promise<bigint> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.paymasterAddress,
        abi: quipPaymasterAbi,
        functionName: "getDeposit",
      })
    );
  }

  /// Read the WOTS+ verifier currently registered for `wallet`. Returns
  /// `(0x0…0, 0x0…0)` if no verifier is set — the paymaster's
  /// `_verifyAndRotate` rejects with `NoVerifierRegistered` for such a wallet.
  async getPqVerifier(wallet: Address): Promise<WinternitzAddress> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.paymasterAddress,
        abi: quipPaymasterAbi,
        functionName: "getPqVerifier",
        args: [wallet],
      })
    );
  }

  async owner(): Promise<Address> {
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.paymasterAddress,
        abi: quipPaymasterAbi,
        functionName: "owner",
      })
    );
  }

  /// Deposit ETH to the paymaster's EntryPoint balance. Anyone can call.
  async deposit(value: bigint, opts: TxOptions = {}): Promise<TransactionReceipt> {
    const contractCall: ContractCallParams = {
      address: this.paymasterAddress,
      abi: quipPaymasterAbi,
      functionName: "deposit",
      args: [],
      value,
      account: this.account,
    };
    return this.executeWrite(contractCall, value, opts);
  }

  /// Register a WOTS+ verifier for `wallet`. Owner-only. Subsequent
  /// sponsored UserOps from `wallet` are validated against this key chain.
  async setPqVerifier(
    wallet: Address,
    verifier: WinternitzAddress,
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const contractCall: ContractCallParams = {
      address: this.paymasterAddress,
      abi: quipPaymasterAbi,
      functionName: "setPqVerifier",
      args: [wallet, verifier],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
  }

  /// Remove the WOTS+ verifier for `wallet`. Owner-only. Subsequent
  /// sponsored UserOps from `wallet` will be rejected with
  /// `NoVerifierRegistered`.
  async removePqVerifier(
    wallet: Address,
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const contractCall: ContractCallParams = {
      address: this.paymasterAddress,
      abi: quipPaymasterAbi,
      functionName: "removePqVerifier",
      args: [wallet],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
  }

  /// Withdraw `amount` wei from the paymaster's EntryPoint deposit to `to`.
  /// Owner-only.
  async withdrawTo(
    to: Address,
    amount: bigint,
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const contractCall: ContractCallParams = {
      address: this.paymasterAddress,
      abi: quipPaymasterAbi,
      functionName: "withdrawTo",
      args: [to, amount],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
  }

  /// Stake `value` wei at the EntryPoint for reputation. Owner-only.
  async addStake(
    unstakeDelaySec: number,
    value: bigint,
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const contractCall: ContractCallParams = {
      address: this.paymasterAddress,
      abi: quipPaymasterAbi,
      functionName: "addStake",
      args: [unstakeDelaySec],
      value,
      account: this.account,
    };
    return this.executeWrite(contractCall, value, opts);
  }

  /// Begin the unstake delay window. Owner-only.
  async unlockStake(opts: TxOptions = {}): Promise<TransactionReceipt> {
    const contractCall: ContractCallParams = {
      address: this.paymasterAddress,
      abi: quipPaymasterAbi,
      functionName: "unlockStake",
      args: [],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
  }

  /// Withdraw unlocked stake to `to`. Owner-only.
  async withdrawStake(
    to: Address,
    opts: TxOptions = {}
  ): Promise<TransactionReceipt> {
    const contractCall: ContractCallParams = {
      address: this.paymasterAddress,
      abi: quipPaymasterAbi,
      functionName: "withdrawStake",
      args: [to],
      account: this.account,
    };
    return this.executeWrite(contractCall, 0n, opts);
  }

  /// Produce a sponsored UserOp by signing the paymaster's approval
  /// digest with the operator's WOTS+ verifier-key signer. Returns a
  /// copy of `userOp` with `paymasterAndData` populated.
  ///
  /// `operatorSigner.sign(...)` auto-burns the current verifier — once
  /// this method returns, that verifier is dead. The next sponsored
  /// UserOp from the same sender must use the rotated `nextVerifier`.
  /// The paymaster's on-chain rotation happens during
  /// `_verifyAndRotate` (when the UserOp is processed by the EntryPoint).
  ///
  /// `nextVerifier` defaults to a freshly generated keypair under
  /// `(vaultId, randomSeed)`. Callers can supply their own for testing
  /// or for pre-derived key material.
  async sponsorUserOp(params: {
    userOp: PackedUserOperation;
    operatorSigner: QuipSigner;
    vaultId: Hex;
    currentVerifier: WinternitzAddress;
    nextVerifier?: WinternitzAddress;
    validUntil?: number;
    validAfter?: number;
    validationGasLimit?: bigint;
    postOpGasLimit?: bigint;
  }): Promise<{
    userOp: PackedUserOperation;
    digest: Hex;
    nextVerifier: WinternitzAddress;
  }> {
    const next =
      params.nextVerifier ??
      params.operatorSigner.generateKeyPair(params.vaultId).publicKey;

    const validUntil = params.validUntil ?? 0;
    const validAfter = params.validAfter ?? 0;

    const { paymasterAndData, digest } = buildSignedPaymasterAndData({
      signer: params.operatorSigner,
      vaultId: params.vaultId,
      paymaster: this.paymasterAddress,
      chainId: BigInt(this.chainId),
      sender: params.userOp.sender,
      nonce: params.userOp.nonce,
      callData: params.userOp.callData,
      currentVerifier: params.currentVerifier,
      nextVerifier: next,
      validUntil,
      validAfter,
      ...(params.validationGasLimit !== undefined && {
        validationGasLimit: params.validationGasLimit,
      }),
      ...(params.postOpGasLimit !== undefined && {
        postOpGasLimit: params.postOpGasLimit,
      }),
    });

    return {
      userOp: { ...params.userOp, paymasterAndData },
      digest,
      nextVerifier: next,
    };
  }

  /// Pre-flight version of a write: returns the prepared tx without sending.
  async estimateWrite(
    functionName:
      | "deposit"
      | "setPqVerifier"
      | "removePqVerifier"
      | "withdrawTo"
      | "addStake"
      | "unlockStake"
      | "withdrawStake",
    args: readonly unknown[],
    value: bigint = 0n,
    opts: TxOptions = {}
  ): Promise<PreparedTx> {
    const contractCall = {
      address: this.paymasterAddress,
      abi: quipPaymasterAbi,
      functionName,
      args,
      value,
      account: this.account,
    } as unknown as ContractCallParams;
    return prepareTx({
      publicClient: this.publicClient,
      contractParams: contractCall,
      totalValue: value,
      opts,
    });
  }

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
}

