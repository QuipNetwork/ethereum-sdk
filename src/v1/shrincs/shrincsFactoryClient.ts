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
import {
  NoVaultFoundError,
  WalletAlreadyExistsError,
} from "../errors.js";
import { assertProviderState, boundChain } from "../internal/providerState.js";
import { getShrincsAddresses } from "./addresses.js";
import {
  CommitmentMismatchError,
  ImplementationDeprecatedError,
  ImplementationNotVettedError,
} from "./errors.js";
import { type ContractCallParams, type TxOptions, prepareTx } from "./gas.js";
import { assertReceiptSuccess } from "./internal/assertReceiptSuccess.js";
import { withDecodedError } from "./internal/decodeError.js";
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

    const vaultId = params.vaultId ?? randomVaultId();

    const existing = (await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress,
        abi: walletFactoryAbi,
        functionName: "wallets",
        args: [vaultId],
      })
    )) as Address;
    if (existing !== zeroAddress) {
      throw new WalletAlreadyExistsError(vaultId);
    }

    const mainKey = params.signer.recoverKeyPair(vaultId, {
      maxSignatures: params.maxSignatures,
    });

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

    // e3r: the factory is the authority for the deploy-auth mode and the
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
      args: [vaultId, mainKey.publicKeyCommitment, index, this.account, initPayload],
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
      vaultId,
      chainId: this.chainId,
      account: this.account,
    });
  }

  /// Resolve an existing wallet by `vaultId`, asserting `signer` reproduces the
  /// installed main-key commitment (`CommitmentMismatchError` otherwise), and
  /// return a bound `ShrincsWalletClient`.
  async getShrincsWallet(
    vaultId: Hex,
    signer: ShrincsSigner
  ): Promise<ShrincsWalletClient> {
    const walletAddress = await this.getShrincsWalletAddress(vaultId);
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
    const keypair = signer.recoverKeyPair(vaultId, {
      maxSignatures: state.maxSignatures,
    });
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

  async getWalletState(vaultId: Hex): Promise<{
    keyVersion: number;
    shrincsPublicKeyCommitment: Hex;
    maxSignatures: number;
    hashSuite: number;
  } | null> {
    const walletAddress = await this.getShrincsWalletAddress(vaultId);
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
    vaultId: Hex;
    keypair: ShrincsKeyPair;
  }): Promise<ShrincsWalletClient | null> {
    const walletAddress = await this.getShrincsWalletAddress(params.vaultId);
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
      vaultId: params.vaultId,
      chainId: this.chainId,
      account: this.account,
    });
  }

  /// The factory-registered wallet address for `vaultId` (`zeroAddress` if none).
  async getShrincsWalletAddress(vaultId: Hex): Promise<Address> {
    return withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress,
        abi: walletFactoryAbi,
        functionName: "wallets",
        args: [vaultId],
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
