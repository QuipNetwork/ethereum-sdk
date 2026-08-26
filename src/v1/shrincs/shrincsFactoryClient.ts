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
  toHex,
  zeroAddress,
} from "viem";
import { randomBytes } from "@noble/ciphers/webcrypto";

import { walletFactoryAbi } from "../abi/WalletFactory.js";
import { getNetworkAddresses } from "../addresses.js";
import { NoVaultFoundError, WalletAlreadyExistsError } from "../errors.js";
import { assertProviderState, boundChain } from "../internal/providerState.js";
import { deployVaultSalt, getShrincsAddresses } from "./addresses.js";
import {
  CommitmentMismatchError,
  ImplementationDeprecatedError,
  ImplementationNotVettedError,
} from "./errors.js";
import { type ContractCallParams, type TxOptions, prepareTx } from "./gas.js";
import { type CostEstimate, estimateTxCost } from "./estimateCost.js";
import { withDecodedError } from "./internal/decodeError.js";
import { assertReceiptSuccess } from "./internal/assertReceiptSuccess.js";
import { encodeDeployAuth, encodeInitPayload } from "./shrincsCodec.js";
import { buildDeployAuthorization } from "./deployAuth.js";
import { type ShrincsKeyPair, type ShrincsSigner } from "./shrincsSigner.js";
import {
  ShrincsWalletClient,
  fetchShrincsWalletState,
} from "./shrincsWalletClient.js";

/// Generate a CSPRNG-backed 32-byte vaultId — the default for `createShrincsWallet`
/// when the caller omits one. The factory's vaultId namespace is GLOBAL (the
/// CREATE3 salt is keyed solely on vaultId), so a predictable vaultId is
/// front-runnable across users and chains; random is the only safe default.
export function randomVaultId(): Hex {
  return toHex(randomBytes(32));
}

/// How the wallet's dedicated ERC-1271 verifier key is specified at creation.
/// There is intentionally NO default derivation: the ERC-1271 key is an
/// independent bundle whose commitment is sealed into the wallet's init
/// immutably, so the caller must choose it explicitly and record how to recover
/// it (exactly as it must for the main `vaultId`). Either:
///   - `{ vaultId, maxSignatures? }`: derive it from the SAME `signer` under a
///     caller-chosen vault branch (recover later via the same `vaultId`), or
///   - `{ commitment }`: supply a precomputed commitment for a fully
///     independent key (e.g. a different signer or an out-of-band key).
export type Erc1271KeySpec =
  | { vaultId: Hex; maxSignatures?: number }
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

/// `estimateCreationCost` prices the exact deployment `createShrincsWallet`
/// would send, so it takes the same inputs: under `e3r` the wallet address,
/// the init payload, and the embedded deploy authorization all derive from the
/// main key, so there is no signer-free quote.
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
  /// Main-key vault branch. Defaults to a CSPRNG-generated 32-byte value.
  vaultId?: Hex;
  /// The dedicated ERC-1271 verifier key. Required and explicit — see
  /// `Erc1271KeySpec` (there is no inferred default).
  erc1271: Erc1271KeySpec;
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

    const { vaultId, contractCall, creationFee } =
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
      vaultId,
      chainId: this.chainId,
      account: this.account,
    });
  }

  /// Price the deployment `createShrincsWallet(params)` would send, without
  /// sending it. Builds the SAME call — same key, same init payload, same
  /// deploy authorization — and runs it through `eth_estimateGas` with the
  /// sender's balance overridden, so an empty account can be quoted. Nothing
  /// is written and no on-chain leaf is consumed.
  ///
  /// Signature safety: the deploy authorization is a signature over a message
  /// fixed by `(chainId, factory, vaultId, owner, erc1271Commitment,
  /// quipDeployChainIndex)` at the deploy leaf reserved for this chain. The
  /// estimate and the eventual deployment sign that one identical message at
  /// that one leaf — a repeated signature of the same message reveals nothing
  /// new, so this is not one-time-leaf reuse.
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

  /// Resolve an existing wallet by `(vaultId, maxSignatures)`, asserting `signer`
  /// reproduces the installed main-key commitment (`CommitmentMismatchError`
  /// otherwise), and return a bound `ShrincsWalletClient`. `maxSignatures` is
  /// required: under `e3r` the wallet address binds to the main-key commitment,
  /// which depends on the key's leaf budget, so it cannot be recovered from the
  /// vault id alone.
  async getShrincsWallet(
    vaultId: Hex,
    signer: ShrincsSigner,
    maxSignatures: number
  ): Promise<ShrincsWalletClient> {
    const keypair = signer.recoverKeyPair(vaultId, { maxSignatures });
    const walletAddress = await this.getShrincsWalletAddress(
      vaultId,
      keypair.publicKeyCommitment
    );
    if (walletAddress === zeroAddress) {
      throw new NoVaultFoundError(vaultId);
    }
    const client = new ShrincsWalletClient({
      walletAddress,
      publicClient: this.publicClient,
      walletClient: this.walletClient,
      signer,
      vaultId,
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

  async getWalletState(
    vaultId: Hex,
    mainCommitment: Hex
  ): Promise<{
    keyVersion: number;
    shrincsPublicKeyCommitment: Hex;
    maxSignatures: number;
    hashSuite: number;
  } | null> {
    const walletAddress = await this.getShrincsWalletAddress(
      vaultId,
      mainCommitment
    );
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
    vaultId: Hex;
    keypair: ShrincsKeyPair;
  }): Promise<ShrincsWalletClient | null> {
    const walletAddress = await this.getShrincsWalletAddress(
      params.vaultId,
      params.keypair.publicKeyCommitment
    );
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
      vaultId: params.vaultId,
      chainId: this.chainId,
      account: this.account,
    });
  }

  /// The factory-registered wallet address for `(vaultId, mainCommitment)`
  /// (`zeroAddress` if none). Under `e3r` the factory keys its registry by the
  /// commitment-bound deploy salt, so resolving a wallet requires the main-key
  /// commitment, not the vault id alone.
  async getShrincsWalletAddress(
    vaultId: Hex,
    mainCommitment: Hex
  ): Promise<Address> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress,
        abi: walletFactoryAbi,
        functionName: "wallets",
        args: [deployVaultSalt(vaultId, mainCommitment)],
      })
    ) as Promise<Address>;
  }

  /// Everything `createShrincsWallet` and `estimateCreationCost` share: recover
  /// the main key, refuse an already-deployed `(vaultId, commitment)`, resolve
  /// the ERC-1271 commitment, sign the deploy authorization against the
  /// factory's live deploy config, and pack the `deploySpecificWalletProxy` call.
  private async buildCreateCall(params: CreateShrincsWalletParams): Promise<{
    vaultId: Hex;
    mainKey: ShrincsKeyPair;
    contractCall: ContractCallParams;
    creationFee: bigint;
  }> {
    const vaultId = params.vaultId ?? randomVaultId();

    const mainKey = params.signer.recoverKeyPair(vaultId, {
      maxSignatures: params.maxSignatures,
    });

    // The factory keys its registry by the commitment-bound deploy salt (`e3r`),
    // so an existing-wallet check must look up `(vaultId, mainCommitment)`.
    const existing = await this.getShrincsWalletAddress(
      vaultId,
      mainKey.publicKeyCommitment
    );
    if (existing !== zeroAddress) {
      throw new WalletAlreadyExistsError(vaultId);
    }

    // Resolve the ERC-1271 verifier commitment from whichever explicit form the
    // caller chose — never inferred from the main key/vaultId.
    let erc1271Commitment: Hex;
    if ("vaultId" in params.erc1271) {
      const erc1271Key = params.signer.recoverKeyPair(params.erc1271.vaultId, {
        maxSignatures: params.erc1271.maxSignatures ?? params.maxSignatures,
      });
      erc1271Commitment = erc1271Key.publicKeyCommitment;
    } else {
      erc1271Commitment = params.erc1271.commitment;
    }

    // the factory is the authority for the deploy-auth mode and the
    // per-chain quipDeployChainIndex; the deploy signature must match exactly
    // what `initialize` rebuilds and verifies against the factory. Read both
    // from the factory rather than assuming, so a misconfigured factory fails
    // loudly instead of producing an unverifiable signature.
    const [deployModeRaw, chainIndexRaw] = (await Promise.all([
      withDecodedError(
        this.publicClient.readContract({
          address: this.factoryAddress,
          abi: walletFactoryAbi,
          functionName: "deployMode",
        })
      ),
      withDecodedError(
        this.publicClient.readContract({
          address: this.factoryAddress,
          abi: walletFactoryAbi,
          functionName: "quipDeployChainIndex",
        })
      ),
    ])) as [number, number];
    const mode = deployModeRaw === 0 ? "stateful" : "stateless";
    const { signature: deploySignature } = buildDeployAuthorization({
      mainKey,
      chainId: this.chainId,
      factoryAddress: this.factoryAddress,
      vaultId,
      owner: this.account,
      erc1271Commitment,
      quipDeployChainIndex: Number(chainIndexRaw),
      mode,
    });
    const deployAuth = encodeDeployAuth(mainKey.publicKey, deploySignature, mode);

    const initPayload = encodeInitPayload({
      mainBundle: mainKey.publicKey,
      erc1271Commitment,
      deployAuth,
    });

    const { contractCall, creationFee } = await this.buildDeploymentCall(
      vaultId,
      mainKey.publicKeyCommitment,
      initPayload
    );
    return { vaultId, mainKey, contractCall, creationFee };
  }

  private async buildDeploymentCall(
    vaultId: Hex,
    mainCommitment: Hex,
    initPayload: Hex
  ): Promise<{ contractCall: ContractCallParams; creationFee: bigint }> {
    const index = await this.resolveImplementationIndex();
    const creationFee = (await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress,
        abi: walletFactoryAbi,
        functionName: "creationFee",
      })
    )) as bigint;

    return {
      creationFee,
      contractCall: {
        address: this.factoryAddress,
        abi: walletFactoryAbi,
        functionName: "deploySpecificWalletProxy",
        args: [vaultId, mainCommitment, index, this.account, initPayload],
        value: creationFee,
        account: this.account as Account | Address,
      },
    };
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
