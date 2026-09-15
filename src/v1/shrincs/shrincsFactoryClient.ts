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
import { NoVaultFoundError, WalletAlreadyExistsError } from "../errors.js";
import { assertProviderState, boundChain } from "../internal/providerState.js";
import { getShrincsAddresses, v1Commitment } from "./addresses.js";
import {
  CommitmentMismatchError,
  ImplementationDeprecatedError,
  ImplementationNotVettedError,
  StatefulTreeSpentError,
  StatelessTreeSpentError,
} from "./errors.js";
import { type ContractCallParams, type TxOptions, prepareTx } from "./gas.js";
import { type CostEstimate, estimateTxCost } from "./estimateCost.js";
import { withDecodedError } from "./internal/decodeError.js";
import { assertReceiptSuccess } from "./internal/assertReceiptSuccess.js";
import {
  encodeInitPayload,
  statefulTreeId,
  statelessTreeId,
} from "./shrincsCodec.js";
import { type ShrincsPublicKey } from "./types.js";
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
///   - `{ publicKey }`: supply the FULL public-key bundle of an independent
///     key (e.g. a different signer or an out-of-band key). A bare commitment
///     is not enough: the wallet's initialize takes the whole bundle so it can
///     derive the commitment on-chain and spend the bundle's trees in the
///     lifetime registries.
export type Erc1271KeySpec =
  | { derivationIndex: number; maxSignatures?: number }
  | { publicKey: ShrincsPublicKey };

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

/// `estimateCreationCost` prices the exact deployment `createShrincsWallet`
/// would send, so it takes the same inputs: the V1 commitment (and therefore
/// the wallet address) and the init payload all derive from the main key, so
/// there is no signer-free quote.
export type EstimateCreationCostParams = CreateShrincsWalletParams;

export interface CreationCostEstimate extends CostEstimate {
  creationFee: bigint;
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
      params.factoryAddress ??
      getNetworkAddresses(params.chainId).WalletFactory;
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

    const { commitment, contractCall, creationFee } =
      await this.buildCreateCall(params);
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

  /// Price the deployment `createShrincsWallet(params)` would send, without
  /// sending it. Builds the SAME call — same key, same commitment, same init
  /// payload — and runs it through `eth_estimateGas` with the sender's balance
  /// overridden, so an empty account can be quoted. Nothing is written and no
  /// on-chain leaf is consumed: under the V1 identity model deployment carries
  /// no signature at all, so estimating is signature-free.
  async estimateCreationCost(
    params: EstimateCreationCostParams,
    opts: TxOptions = {}
  ): Promise<CreationCostEstimate> {
    await assertProviderState({
      publicClient: this.publicClient,
      expectedChainId: this.chainId,
    });

    const { contractCall, creationFee } = await this.buildCreateCall(params);
    const estimate = await estimateTxCost({
      publicClient: this.publicClient,
      account: this.account,
      contractCall,
      totalValue: creationFee,
      opts,
    });

    return { ...estimate, creationFee };
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
    const erc1271C = this.resolveErc1271Bundle(
      signer,
      erc1271,
      maxSignatures
    ).publicKeyCommitment;
    const commitment = v1Commitment(statefulC, erc1271C, owner);
    const walletAddress = await this.getShrincsWalletAddress(
      statefulC,
      erc1271C,
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
    const state = await fetchShrincsWalletState(
      this.publicClient,
      walletAddress
    );
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
    const state = await fetchShrincsWalletState(
      this.publicClient,
      walletAddress
    );
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
  /// `(statefulC, erc1271C, owner)` (`zeroAddress` if none). The mapping is
  /// keyed by `commitment` (CREATE3 salt == commitment).
  async getShrincsWalletAddress(
    statefulC: Hex,
    erc1271C: Hex,
    owner: Address
  ): Promise<Address> {
    return this.readWallets(v1Commitment(statefulC, erc1271C, owner));
  }

  private resolveErc1271Bundle(
    signer: ShrincsSigner,
    erc1271: Erc1271KeySpec,
    defaultMaxSignatures: number
  ): ShrincsPublicKey {
    if ("derivationIndex" in erc1271) {
      return signer.recoverKeyPair(erc1271.derivationIndex, {
        maxSignatures: erc1271.maxSignatures ?? defaultMaxSignatures,
      }).publicKey;
    }
    return erc1271.publicKey;
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

  /// Everything `createShrincsWallet` and `estimateCreationCost` share: recover
  /// the main key, resolve the ERC-1271 bundle, compute the V1 commitment
  /// for `(statefulC, erc1271C, owner)`, refuse an already-deployed identity,
  /// and pack the `deploySpecificWalletProxy` call.
  private async buildCreateCall(params: CreateShrincsWalletParams): Promise<{
    commitment: Hex;
    mainKey: ShrincsKeyPair;
    contractCall: ContractCallParams;
    creationFee: bigint;
  }> {
    const mainKey = params.signer.recoverKeyPair(params.derivationIndex, {
      maxSignatures: params.maxSignatures,
    });
    const statefulC = mainKey.publicKeyCommitment;
    const erc1271Bundle = this.resolveErc1271Bundle(
      params.signer,
      params.erc1271,
      params.maxSignatures
    );
    const erc1271C = erc1271Bundle.publicKeyCommitment;
    // Deploy-time mirror of the wallet's install registries: initialize spends
    // all four trees (main + ERC-1271, stateful + stateless), so a 1271 bundle
    // sharing a tree with the main bundle reverts on-chain. Same order as the
    // wallet: the main bundle installs first, so the 1271 install trips.
    const erc1271StatefulTree = statefulTreeId(erc1271Bundle.statefulPublicKey);
    if (
      erc1271StatefulTree === statefulTreeId(mainKey.publicKey.statefulPublicKey)
    ) {
      throw new StatefulTreeSpentError(erc1271StatefulTree);
    }
    const erc1271StatelessTree = statelessTreeId(
      erc1271Bundle.pkSeed,
      erc1271Bundle.hypertreeRoot
    );
    if (
      erc1271StatelessTree ===
      statelessTreeId(mainKey.publicKey.pkSeed, mainKey.publicKey.hypertreeRoot)
    ) {
      throw new StatelessTreeSpentError(erc1271StatelessTree);
    }
    const owner = this.account;
    const commitment = v1Commitment(statefulC, erc1271C, owner);

    const existing = await this.getShrincsWalletAddress(
      statefulC,
      erc1271C,
      owner
    );
    if (existing !== zeroAddress) {
      throw new WalletAlreadyExistsError(commitment);
    }

    const initPayload = encodeInitPayload({
      mainBundle: mainKey.publicKey,
      erc1271Bundle,
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
    return { commitment, mainKey, contractCall, creationFee };
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
