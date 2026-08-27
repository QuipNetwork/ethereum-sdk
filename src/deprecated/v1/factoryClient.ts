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
  type EIP1193Provider,
  type TransactionReceipt,
  createPublicClient,
  createWalletClient,
  custom,
  keccak256,
  toHex,
  zeroAddress,
  parseEventLogs,
} from "viem";
import { randomBytes } from "@noble/ciphers/webcrypto";

import { walletFactoryAbi } from "../../v1/abi/WalletFactory.js";
import {
  getVaultAddress,
  getNetworkAddresses,
  CHAIN_IDS,
} from "../../v1/addresses.js";
import { QuipSigner } from "./signer.js";
import { WOTSPlusImplementationClient } from "./walletClient.js";
import { withDecodedError } from "../../v1/internal/decodeError.js";
import { tryMulticall } from "../../v1/internal/multicall.js";
import {
  assertProviderState,
  boundChain,
} from "../../v1/internal/providerState.js";
import {
  type TxOptions,
  type ContractCallParams,
  prepareTx,
} from "../../v1/gas.js";
import {
  WalletNotInitializedError,
  WalletAlreadyExistsError,
  NoVaultFoundError,
  InvalidSignerError,
  NotConnectedError,
  PartialMulticallResultError,
} from "./errors.js";
import {
  type WinternitzAddress,
  encodeInit,
  MAX_KEYS,
} from "./wotsCodec.js";

/// Generate a CSPRNG-backed 32-byte vaultId. Default for `createWallet`
/// when the caller omits `opts.vaultId`. A random vaultId is the only
/// safe default given that the factory's vaultId namespace is GLOBAL
/// (CREATE3 salt depends solely on vaultId); a predictable vaultId is
/// front-runnable across users and across chains.
export function randomVaultId(): Hex {
  return toHex(randomBytes(32));
}

/// Aggregated factory state — one multicall round-trip's worth of view
/// reads. Useful for an admin dashboard or pre-flight overview.
/// NOTE: no `pendingOwner` — the UUPS factory uses Solady Ownable, whose
/// two-step handover is keyed by candidate address
/// (`ownershipHandoverExpiresAt(addr)`), not a single pending-owner slot.
export interface FactoryState {
  owner: Address;
  creationFee: bigint;
  executeFee: bigint;
  maxFee: bigint;
  latestWalletImpl: Address;
  vettedCodeCount: bigint;
}

/** @deprecated WOTS+ family sunset — superseded by SHRINCS (`ShrincsFactoryClient` in `./v1/shrincs`). Fully functional for existing deployments. */
export class QuipClient {
  private publicClient: PublicClient;
  private walletClient: WalletClient;
  private account?: Address;
  private factoryAddress?: Address;
  private chainId?: number;
  private initializationPromise: Promise<void>;

  /**
   * Create a QuipClient instance
   * Works with any EIP-1193 compatible provider
   *
   * @param provider - An EIP-1193 compatible provider
   */
  constructor(provider: EIP1193Provider) {
    const transport = custom(provider);
    this.publicClient = createPublicClient({ transport });
    this.walletClient = createWalletClient({ transport });
    this.initializationPromise = this.initialize();
  }

  /**
   * Factory method for creating QuipClient instances
   * Provides a cleaner async initialization pattern
   */
  static async create(
    provider: EIP1193Provider
  ): Promise<QuipClient> {
    const client = new QuipClient(provider);
    await client.initializationPromise;
    return client;
  }

  private async initialize() {
    await this.detectNetwork();
    await this.setAccount();
    await this.setWalletFactory();
  }

  private async setAccount() {
    const [address] = await this.walletClient.getAddresses();
    this.account = address;
  }

  private async detectNetwork() {
    this.chainId = await this.publicClient.getChainId();
  }

  private async setWalletFactory() {
    const addresses = getNetworkAddresses(this.chainId);
    this.factoryAddress = addresses.WalletFactory;
  }

  /**
   * Get the current chain ID
   */
  getChainId(): number {
    if (!this.chainId) {
      throw new WalletNotInitializedError();
    }
    return this.chainId;
  }

  /**
   * Check if connected to MIDL network
   */
  isMidlNetwork(): boolean {
    return this.chainId === CHAIN_IDS.MIDL_TESTNET;
  }

  /**
   * Get the connected wallet's owner address
   */
  async getOwnerAddress(): Promise<Address> {
    await this.initializationPromise;
    if (!this.account) {
      throw new NotConnectedError();
    }
    return this.account;
  }

  async getCreationFee(): Promise<bigint> {
    await this.initializationPromise;
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress!,
        abi: walletFactoryAbi,
        functionName: "creationFee",
      })
    );
  }

  /// Deploy a new WOTSPlusImplementation via `deployLatestWalletProxy`. The SDK
  /// generates every key under `quipSigner`: one disaster recovery key,
  /// one ownership key, ten transaction keys, ten recovery keys, ten
  /// verification keys (the always-10 keyset invariant).
  /// Caller-supplied key material is intentionally NOT accepted —
  /// every `publicSeed` is recoverable later from on-chain state plus
  /// `quipSigner.recoverKeyPair(vaultId, publicSeed)`, so the user's only
  /// off-chain backup obligation is the `quantumSecret` itself.
  ///
  /// `vaultId` defaults to a CSPRNG-generated 32-byte value. The factory's
  /// vaultId namespace is GLOBAL (CREATE3 salt is keyed only on vaultId),
  /// so a predictable vaultId is front-runnable: an attacker who observes
  /// or guesses your intended vaultId can deploy at the same address first,
  /// pinning your funds in a wallet whose PQ keys they control. Random is
  /// the only safe default. Override only if you have a specific reason to
  /// reproduce an address (e.g. cross-chain mirror — see TODO_SDK.md
  /// §"Cross-chain vaultId capture").
  async createWallet(
    quipSigner: QuipSigner,
    opts: TxOptions & { vaultId?: Hex } = {}
  ): Promise<WOTSPlusImplementationClient> {
    const { vaultId: providedVaultId, ...txOpts } = opts;
    const vaultId = providedVaultId ?? randomVaultId();
    return this.deployWallet(
      vaultId,
      quipSigner,
      {
        functionName: "deployLatestWalletProxy",
        argsExceptInitPayload: () =>
          [vaultId, keccak256(vaultId), this.account!] as const,
      },
      txOpts
    );
  }

  /// Deploy a new WOTSPlusImplementation against the implementation at a specific
  /// index in the factory's vetted set (via `deploySpecificWalletProxy`).
  /// Use this when the caller explicitly wants an older, still-vetted
  /// implementation rather than the latest. Same key-generation and
  /// random-vaultId-default policy as `createWallet`.
  async createWalletWithImplementation(
    quipSigner: QuipSigner,
    index: bigint,
    opts: TxOptions & { vaultId?: Hex } = {}
  ): Promise<WOTSPlusImplementationClient> {
    const { vaultId: providedVaultId, ...txOpts } = opts;
    const vaultId = providedVaultId ?? randomVaultId();
    return this.deployWallet(
      vaultId,
      quipSigner,
      {
        functionName: "deploySpecificWalletProxy",
        argsExceptInitPayload: () =>
          [vaultId, keccak256(vaultId), index, this.account!] as const,
      },
      txOpts
    );
  }

  /// Shared write pipeline behind every wallet-deployment factory method:
  /// generates the wallet's initial key material, packs the init payload,
  /// preflights / sends / waits, decodes `WalletDeployed` from the receipt,
  /// and returns a bound `WOTSPlusImplementationClient`.
  private async deployWallet(
    vaultId: Hex,
    quipSigner: QuipSigner,
    spec: {
      functionName: "deployLatestWalletProxy" | "deploySpecificWalletProxy";
      argsExceptInitPayload: () => readonly unknown[];
    },
    opts: TxOptions
  ): Promise<WOTSPlusImplementationClient> {
    await this.initializationPromise;

    // Fail closed if the provider switched chain or dropped the bound
    // account since `initialize()`. Wrong-chain deploys are otherwise
    // silent: the supported EVM chains share CREATE3-deterministic
    // factory addresses, so a stale chainId would deploy the wallet on
    // whichever chain the provider is now pointed at.
    await assertProviderState({
      publicClient: this.publicClient,
      expectedChainId: this.chainId!,
      walletClient: this.walletClient,
      expectedAccount: this.account!,
    });

    const creationFee = await this.getCreationFee();

    const existingWalletAddress = await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress!,
        abi: walletFactoryAbi,
        functionName: "wallets",
        args: [vaultId],
      })
    );

    if (existingWalletAddress !== zeroAddress) {
      throw new WalletAlreadyExistsError(vaultId);
    }

    const disaster = quipSigner.generateKeyPair(vaultId).publicKey;
    const ownership = quipSigner.generateKeyPair(vaultId).publicKey;
    const transactionKeys: WinternitzAddress[] = Array.from(
      { length: MAX_KEYS },
      () => quipSigner.generateKeyPair(vaultId).publicKey
    );
    const recoveryKeys: WinternitzAddress[] = Array.from(
      { length: MAX_KEYS },
      () => quipSigner.generateKeyPair(vaultId).publicKey
    );
    const verificationKeys: WinternitzAddress[] = Array.from(
      { length: MAX_KEYS },
      () => quipSigner.generateKeyPair(vaultId).publicKey
    );

    const initPayload = encodeInit(
      disaster,
      ownership,
      transactionKeys,
      recoveryKeys,
      verificationKeys
    );

    const contractCall: ContractCallParams = {
      address: this.factoryAddress!,
      abi: walletFactoryAbi,
      functionName: spec.functionName,
      args: [...spec.argsExceptInitPayload(), initPayload],
      value: creationFee,
      account: this.account!,
    };
    const prepared = await prepareTx({
      publicClient: this.publicClient,
      contractParams: contractCall,
      totalValue: creationFee,
      opts,
    });

    const hash = await withDecodedError(
      this.walletClient.writeContract({
        // Backstop behind `assertProviderState`: a non-null chain
        // re-enables viem's own chain assertion inside `writeContract`.
        chain: boundChain(this.chainId!),
        ...contractCall,
        gas: prepared.gas,
        ...prepared.fees,
        ...(prepared.nonce !== undefined && { nonce: prepared.nonce }),
      } as Parameters<WalletClient["writeContract"]>[0])
    );

    const receipt: TransactionReceipt =
      await this.publicClient.waitForTransactionReceipt({ hash });

    const logs = parseEventLogs({
      abi: walletFactoryAbi,
      logs: receipt.logs,
      eventName: "WalletDeployed",
    });
    const newWalletAddress = logs[0].args.quip;

    return new WOTSPlusImplementationClient(
      quipSigner,
      vaultId,
      newWalletAddress,
      this.publicClient,
      this.walletClient,
      this.account!,
      this.chainId!
    );
  }

  /// Resolve an existing wallet by `vaultId` and return a `WOTSPlusImplementationClient`
  /// bound to it.
  ///
  /// **Signer check is head-key-only.** Before returning, this method
  /// regenerates the keypair for `keyAt(Transaction, 0)` under `quipSigner`
  /// and asserts the `publicKeyHash` matches — throwing `InvalidSignerError`
  /// on mismatch. This proves the signer can produce *one specific* key
  /// (whichever entry currently sits at index 0 of the transaction keyset),
  /// not that it owns every key in the wallet.
  ///
  /// Why this is loose:
  ///   - `EnumerableSet` swap-pop rotation means the head slot can hold any
  ///     surviving keyset entry, not a stable "primary".
  ///   - A wallet operated concurrently by multiple signers (rare, but legal)
  ///     can have a head whose private key only one of them controls — the
  ///     other still gets `InvalidSignerError` here, even though both are
  ///     valid co-signers.
  ///   - A signer that recovered from `quantumSecret` alone — without
  ///     having seen prior rotations — passes this check as long as it can
  ///     reproduce whatever public seed is at index 0 today.
  ///
  /// Callers needing stronger guarantees should call `getKeyset(Transaction)`
  /// after construction and verify every entry against `quipSigner` directly.
  /// See `SDK_README.md` → "What the SDK does NOT guarantee".
  async getVault(
    vaultId: Hex,
    quipSigner: QuipSigner
  ): Promise<WOTSPlusImplementationClient> {
    await this.initializationPromise;

    const walletAddress = await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress!,
        abi: walletFactoryAbi,
        functionName: "wallets",
        args: [vaultId],
      })
    );

    if (walletAddress === zeroAddress) {
      throw new NoVaultFoundError(vaultId);
    }

    const client = new WOTSPlusImplementationClient(
      quipSigner,
      vaultId,
      walletAddress,
      this.publicClient,
      this.walletClient,
      this.account!,
      this.chainId!
    );

    const headKey = await client.getHeadTransactionKey();
    const keypair = quipSigner.recoverKeyPair(vaultId, headKey.publicSeed);
    if (keypair.publicKey.publicKeyHash !== headKey.publicKeyHash) {
      throw new InvalidSignerError();
    }
    return client;
  }

  async getVaultAddress(vaultId: Hex): Promise<Address> {
    await this.initializationPromise;
    return getVaultAddress(vaultId, this.chainId);
  }

  async getVaults(): Promise<Map<string, Address>> {
    await this.initializationPromise;
    await assertProviderState({
      publicClient: this.publicClient,
      expectedChainId: this.chainId!,
    });
    // Re-resolve the active account on every call instead of using the
    // `initialize()`-time snapshot: a read should reflect the provider's
    // current account, not silently return the previous account's vaults
    // after the user switches.
    const [account] = await this.walletClient.getAddresses();
    if (!account) {
      throw new NotConnectedError();
    }

    // One multicall: `getVaultIds(owner)` + `getWallets(owner)` return
    // parallel-indexed snapshots when read in the same block. Avoids
    // the legacy `1 + N` round-trip pattern.
    const results = await tryMulticall(
      this.publicClient,
      [
        {
          address: this.factoryAddress!,
          abi: walletFactoryAbi,
          functionName: "getVaultIds" as const,
          args: [account] as const,
        },
        {
          address: this.factoryAddress!,
          abi: walletFactoryAbi,
          functionName: "getWallets" as const,
          args: [account] as const,
        },
      ],
      { chainId: this.chainId }
    );

    const failures: { label: string; error: Error }[] = [];
    if (results[0].status === "failure")
      failures.push({ label: "getVaultIds", error: results[0].error });
    if (results[1].status === "failure")
      failures.push({ label: "getWallets", error: results[1].error });
    if (failures.length > 0) throw new PartialMulticallResultError(failures);

    const vaultIds = (results[0] as { status: "success"; result: Hex[] })
      .result;
    const walletAddrs = (
      results[1] as { status: "success"; result: Address[] }
    ).result;

    const vaultMap = new Map<string, Address>();
    for (let i = 0; i < vaultIds.length; i++) {
      vaultMap.set(vaultIds[i], walletAddrs[i]);
    }
    return vaultMap;
  }

  /// Number of entries in the factory's vetted-codehash set (active +
  /// deprecated). Indices are insertion-order; pair with `getVettedCodeAt`
  /// to enumerate.
  async getVettedCodeCount(): Promise<bigint> {
    await this.initializationPromise;
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress!,
        abi: walletFactoryAbi,
        functionName: "getVettedCodeCount",
      })
    );
  }

  /// Codehash at `index` in the vetted set (insertion order). The index is
  /// the same one consumed by `deploySpecificWalletProxy` /
  /// `createWalletWithImplementation`.
  async getVettedCodeAt(index: bigint): Promise<Hex> {
    await this.initializationPromise;
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress!,
        abi: walletFactoryAbi,
        functionName: "getVettedCodeAt",
        args: [index],
      })
    );
  }

  /// Index of `codehash` in the vetted set, or `type(uint256).max` when
  /// not vetted.
  async getVettedCodeIndex(codehash: Hex): Promise<bigint> {
    await this.initializationPromise;
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress!,
        abi: walletFactoryAbi,
        functionName: "getVettedCodeIndex",
        args: [codehash],
      })
    );
  }

  /// Implementation address currently bound to `codehash`, or
  /// `address(0)` when the codehash is not vetted. The binding can be
  /// re-pointed by `undeprecateImplementation` so the result is the
  /// most-recent address registered against this codehash, not
  /// necessarily the original `vetImplementation` caller's address.
  async getImplementationByCodehash(codehash: Hex): Promise<Address> {
    await this.initializationPromise;
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress!,
        abi: walletFactoryAbi,
        functionName: "vettedWalletImpls",
        args: [codehash],
      })
    );
  }

  /// `true` when the supplied codehash is currently deprecated (still
  /// vetted, but `deployLatestWalletProxy` skips it and a wallet
  /// targeting it via `upgradeToAndCall` reverts with
  /// `ImplementationDeprecated`).
  async isCodeDeprecated(codehash: Hex): Promise<boolean> {
    await this.initializationPromise;
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress!,
        abi: walletFactoryAbi,
        functionName: "deprecatedImpls",
        args: [codehash],
      })
    );
  }

  /// Most-recently-vetted active implementation address. Used as the
  /// target by `deployLatestWalletProxy`.
  async latestWalletImpl(): Promise<Address> {
    await this.initializationPromise;
    return await withDecodedError(
      this.publicClient.readContract({
        address: this.factoryAddress!,
        abi: walletFactoryAbi,
        functionName: "latestWalletImpl",
      })
    );
  }

  /// Per-chain `QuipPaymaster` address as registered in
  /// `NETWORK_ADDRESSES`. Returns `address(0)` for chains where the
  /// paymaster has not been deployed yet — callers using the sponsored
  /// flow should treat zero as "no paymaster available on this chain".
  getPaymasterAddress(): Address {
    if (this.chainId === undefined) {
      throw new WalletNotInitializedError();
    }
    return getNetworkAddresses(this.chainId).QuipPaymaster;
  }

  /// Snapshot of factory-level fees, ownership, and vetted impl pointer in
  /// a single multicall round-trip.
  async getFactoryState(): Promise<FactoryState> {
    await this.initializationPromise;
    const calls = [
      { address: this.factoryAddress!, abi: walletFactoryAbi, functionName: "owner" as const },
      { address: this.factoryAddress!, abi: walletFactoryAbi, functionName: "creationFee" as const },
      { address: this.factoryAddress!, abi: walletFactoryAbi, functionName: "executeFee" as const },
      { address: this.factoryAddress!, abi: walletFactoryAbi, functionName: "MAX_FEE" as const },
      { address: this.factoryAddress!, abi: walletFactoryAbi, functionName: "latestWalletImpl" as const },
      { address: this.factoryAddress!, abi: walletFactoryAbi, functionName: "getVettedCodeCount" as const },
    ];

    const results = await tryMulticall(this.publicClient, calls, {
      chainId: this.chainId,
    });

    const labels = [
      "owner",
      "creationFee",
      "executeFee",
      "MAX_FEE",
      "latestWalletImpl",
      "getVettedCodeCount",
    ] as const;

    const failures: { label: string; error: Error }[] = [];
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.status === "failure") {
        failures.push({ label: labels[i], error: r.error });
      }
    }
    if (failures.length > 0) {
      throw new PartialMulticallResultError(failures);
    }

    return {
      owner: (results[0] as { status: "success"; result: Address }).result,
      creationFee: (results[1] as { status: "success"; result: bigint }).result,
      executeFee: (results[2] as { status: "success"; result: bigint }).result,
      maxFee: (results[3] as { status: "success"; result: bigint }).result,
      latestWalletImpl: (results[4] as { status: "success"; result: Address }).result,
      vettedCodeCount: (results[5] as { status: "success"; result: bigint }).result,
    };
  }
}
