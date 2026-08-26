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
  keccak256,
  maxUint256,
  parseEventLogs,
  zeroAddress,
} from "viem";

import { walletFactoryAbi } from "../abi/WalletFactory.js";
import { getNetworkAddresses } from "../addresses.js";
import {
  NoVaultFoundError,
  WalletAlreadyExistsError,
} from "../errors.js";
import { assertProviderState, boundChain } from "../internal/providerState.js";
import { getShrincsAddresses, v1Commitment } from "./addresses.js";
import {
  CommitmentMismatchError,
  ImplementationDeprecatedError,
  ImplementationNotVettedError,
} from "./errors.js";
import { type ContractCallParams, type TxOptions, prepareTx } from "./gas.js";
import { assertReceiptSuccess } from "./internal/assertReceiptSuccess.js";
import { withDecodedError } from "./internal/decodeError.js";
import { encodeInitPayload } from "./shrincsCodec.js";
import { type ShrincsKeyPair, type ShrincsSigner } from "./shrincsSigner.js";
import {
  ShrincsWalletClient,
  fetchShrincsWalletState,
} from "./shrincsWalletClient.js";

/// How the wallet's dedicated ERC-1271 verifier key is specified at creation.
/// There is intentionally NO default derivation: the ERC-1271 key is an
/// independent bundle whose commitment is sealed into the wallet's init
/// immutably, so the caller must choose it explicitly and record how to recover
/// it (exactly as it must for the main `derivationIndex`). Either:
///   - `{ derivationIndex, maxSignatures? }`: derive it from the SAME `signer`
///     under a caller-chosen index (recover later via the same index), or
///   - `{ commitment }`: supply a precomputed commitment for a fully
///     independent key (e.g. a different signer or an out-of-band key).
export type Erc1271KeySpec =
  | { derivationIndex: number; maxSignatures?: number }
  | { commitment: Hex };

export interface ShrincsFactoryClientParams {
  publicClient: PublicClient;
  walletClient: WalletClient;
  account: Address;
  chainId: number;
  /// WalletFactory address. Defaults to the v1 per-chain registry entry.
  factoryAddress?: Address;
  /// ShrincsWallet implementation singleton. Defaults to the Shrincs registry
  /// entry; the factory deploys a proxy against whichever vetted index this
  /// implementation occupies.
  walletImplementation?: Address;
}

export interface CreateShrincsWalletParams {
  /// Source of the main key material (master-secret-derived).
  signer: ShrincsSigner;
  /// Stateful signature budget baked into the main key's commitment. Must match
  /// the value passed to `signer.recoverKeyPair(...)` for every later signature.
  maxSignatures: number;
  /// Main-key derivation index. The V1 commitment is computed from the
  /// resulting commitments and the factory account (the intended owner).
  derivationIndex: number;
  /// The dedicated ERC-1271 verifier key. Required and explicit — see
  /// `Erc1271KeySpec` (there is no inferred default).
  erc1271: Erc1271KeySpec;
}

export interface GetShrincsWalletParams {
  derivationIndex: number;
  erc1271: Erc1271KeySpec;
  /// Owner used at creation (the `to` argument). Bound into the V1 commitment.
  owner: Address;
  signer: ShrincsSigner;
  maxSignatures: number;
}

/// Deploys `ShrincsWallet` proxies via the shared `WalletFactory` (its
/// `deploySpecificWalletProxy` is impl-generic — the Shrincs implementation is
/// chosen from the factory's vetted-codehash set) and resolves existing ones.
/// Mirrors v1 `QuipClient.createWallet`, but builds the Shrincs init payload and
/// returns a bound `ShrincsWalletClient`.
export class ShrincsFactoryClient {
  readonly chainId: number;
  readonly account: Address;
  readonly factoryAddress: Address;
  readonly walletImplementation: Address;

  private readonly publicClient: PublicClient;
  private readonly walletClient: WalletClient;

  constructor(params: ShrincsFactoryClientParams) {
    this.publicClient = params.publicClient;
    this.walletClient = params.walletClient;
    this.account = params.account;
    this.chainId = params.chainId;
    this.factoryAddress =
      params.factoryAddress ?? getNetworkAddresses(params.chainId).WalletFactory;
    this.walletImplementation =
      params.walletImplementation ??
      getShrincsAddresses(params.chainId).ShrincsWalletImplementation;
  }

  /// Deploy a fresh `ShrincsWallet`. Derives the main key + an ERC-1271 verifier
  /// key from `signer`, packs the init payload, deploys the proxy against the
  /// vetted Shrincs implementation, and returns a bound `ShrincsWalletClient`.
  async createShrincsWallet(
    params: CreateShrincsWalletParams,
    opts: TxOptions = {}
  ): Promise<ShrincsWalletClient> {
    await assertProviderState({
      publicClient: this.publicClient,
      expectedChainId: this.chainId,
      walletClient: this.walletClient,
      expectedAccount: this.account,
    });

    const mainKey = params.signer.recoverKeyPair(params.derivationIndex, {
      maxSignatures: params.maxSignatures,
    });
    const statefulC = mainKey.publicKeyCommitment;
    const statelessC = this.resolveErc1271Commitment(
      params.signer,
      params.erc1271,
      params.maxSignatures
    );
    const owner = this.account;
    const commitment = v1Commitment(statefulC, statelessC, owner);

    const existing = await this.getShrincsWalletAddress(
      statefulC,
      statelessC,
      owner
    );
    if (existing !== zeroAddress) {
      throw new WalletAlreadyExistsError(commitment);
    }

    const initPayload = encodeInitPayload({
      mainBundle: mainKey.publicKey,
      erc1271Commitment: statelessC,
    });

    const index = await this.resolveImplementationIndex();
    const creationFee = (await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress,
        abi: walletFactoryAbi,
        functionName: "creationFee",
      })
    )) as bigint;

    const contractCall: ContractCallParams = {
      address: this.factoryAddress,
      abi: walletFactoryAbi,
      functionName: "deploySpecificWalletProxy",
      args: [commitment, index, this.account, initPayload],
      value: creationFee,
      account: this.account as Account | Address,
    };
    const prepared = await prepareTx({
      publicClient: this.publicClient,
      contractParams: contractCall,
      totalValue: creationFee,
      opts,
    });
    const hash = await withDecodedError(
      this.walletClient.writeContract({
        chain: boundChain(this.chainId),
        ...contractCall,
        gas: prepared.gas,
        ...prepared.fees,
        ...(prepared.nonce !== undefined && { nonce: prepared.nonce }),
      } as unknown as Parameters<WalletClient["writeContract"]>[0])
    );

    const receipt: TransactionReceipt = assertReceiptSuccess(
      await this.publicClient.waitForTransactionReceipt({ hash })
    );
    const logs = parseEventLogs({
      abi: walletFactoryAbi,
      logs: receipt.logs,
      eventName: "WalletDeployed",
    });
    const walletAddress = logs[0].args.quip as Address;

    return new ShrincsWalletClient({
      walletAddress,
      publicClient: this.publicClient,
      walletClient: this.walletClient,
      signer: params.signer,
      commitment,
      derivationIndex: params.derivationIndex,
      chainId: this.chainId,
      account: this.account,
    });
  }

  /// Resolve an existing wallet from its derivation index, ERC-1271 spec, and
  /// original owner. Recomputes the V1 commitment (and therefore the address)
  /// from those inputs, asserts `signer` reproduces the installed main-key
  /// commitment (`CommitmentMismatchError` otherwise), and returns a bound
  /// `ShrincsWalletClient`.
  async getShrincsWallet(
    params: GetShrincsWalletParams
  ): Promise<ShrincsWalletClient> {
    const { derivationIndex, erc1271, owner, signer, maxSignatures } = params;
    const keypair = signer.recoverKeyPair(derivationIndex, { maxSignatures });
    const statefulC = keypair.publicKeyCommitment;
    const statelessC = this.resolveErc1271Commitment(
      signer,
      erc1271,
      maxSignatures
    );
    const commitment = v1Commitment(statefulC, statelessC, owner);
    const walletAddress = await this.getShrincsWalletAddress(
      statefulC,
      statelessC,
      owner
    );
    if (walletAddress === zeroAddress) {
      throw new NoVaultFoundError(commitment);
    }
    const client = new ShrincsWalletClient({
      walletAddress,
      publicClient: this.publicClient,
      walletClient: this.walletClient,
      signer,
      commitment,
      derivationIndex,
      chainId: this.chainId,
      account: this.account,
    });

    const state = await client.getWalletState();
    if (
      keypair.publicKeyCommitment.toLowerCase() !==
      state.shrincsPublicKeyCommitment.toLowerCase()
    ) {
      throw new CommitmentMismatchError(
        keypair.publicKeyCommitment,
        state.shrincsPublicKeyCommitment
      );
    }
    return client;
  }

  async getWalletState(commitment: Hex): Promise<{
    keyVersion: number;
    shrincsPublicKeyCommitment: Hex;
    maxSignatures: number;
    hashSuite: number;
  } | null> {
    const walletAddress = await this.readWallets(commitment);
    if (walletAddress === zeroAddress) return null;
    const state = await fetchShrincsWalletState(this.publicClient, walletAddress);
    return {
      keyVersion: Number(state.keyVersion),
      shrincsPublicKeyCommitment: state.shrincsPublicKeyCommitment,
      maxSignatures: state.maxSignatures,
      hashSuite: state.hashSuite,
    };
  }

  async openShrincsWallet(params: {
    commitment: Hex;
    keypair: ShrincsKeyPair;
  }): Promise<ShrincsWalletClient | null> {
    const walletAddress = await this.readWallets(params.commitment);
    if (walletAddress === zeroAddress) return null;
    const state = await fetchShrincsWalletState(this.publicClient, walletAddress);
    if (
      params.keypair.publicKeyCommitment.toLowerCase() !==
      state.shrincsPublicKeyCommitment.toLowerCase()
    ) {
      throw new CommitmentMismatchError(
        params.keypair.publicKeyCommitment,
        state.shrincsPublicKeyCommitment
      );
    }
    return new ShrincsWalletClient({
      walletAddress,
      publicClient: this.publicClient,
      walletClient: this.walletClient,
      keypair: params.keypair,
      commitment: params.commitment,
      chainId: this.chainId,
      account: this.account,
    });
  }

  /// The factory-registered wallet address for the V1 identity
  /// `(statefulC, statelessC, owner)` (`zeroAddress` if none). The mapping is
  /// keyed by `commitment` (CREATE3 salt == commitment).
  async getShrincsWalletAddress(
    statefulC: Hex,
    statelessC: Hex,
    owner: Address
  ): Promise<Address> {
    return this.readWallets(v1Commitment(statefulC, statelessC, owner));
  }

  private resolveErc1271Commitment(
    signer: ShrincsSigner,
    erc1271: Erc1271KeySpec,
    defaultMaxSignatures: number
  ): Hex {
    if ("derivationIndex" in erc1271) {
      return signer.recoverKeyPair(erc1271.derivationIndex, {
        maxSignatures: erc1271.maxSignatures ?? defaultMaxSignatures,
      }).publicKeyCommitment;
    }
    return erc1271.commitment;
  }

  private async readWallets(id: Hex): Promise<Address> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress,
        abi: walletFactoryAbi,
        functionName: "wallets",
        args: [id],
      })
    ) as Promise<Address>;
  }

  /// Vetted-set index of the Shrincs implementation, resolved from its on-chain
  /// codehash. Throws `ImplementationNotVettedError` if the implementation is not
  /// in the factory's vetted set (or not deployed on this chain). Throws
  /// `ImplementationDeprecatedError` if the vetted codehash has been sunset.
  private async resolveImplementationIndex(): Promise<bigint> {
    const code = await this.publicClient.getCode({
      address: this.walletImplementation,
    });
    if (!code || code === "0x") {
      throw new ImplementationNotVettedError();
    }
    const codehash = keccak256(code);
    const index = (await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress,
        abi: walletFactoryAbi,
        functionName: "getVettedCodeIndex",
        args: [codehash],
      })
    )) as bigint;
    if (index === maxUint256) {
      throw new ImplementationNotVettedError();
    }
    const deprecated = (await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress,
        abi: walletFactoryAbi,
        functionName: "deprecatedImpls",
        args: [codehash],
      })
    )) as boolean;
    if (deprecated) {
      throw new ImplementationDeprecatedError();
    }
    return index;
  }
}
