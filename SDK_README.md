# Quip Ethereum SDK — Reference

`@quip.network/ethereum-sdk` is a TypeScript SDK for post-quantum-secured wallets on EVM chains. This document is the operational reference: critical invariants, architectural responsibilities, and the rules consumers must follow.

For installation and a quickstart, see the package `README.md`. This file is the "what you need to know to use this correctly" companion.

> ⚠️ **The `./v0` export is legacy.** It targets the original pre-v1 contract deployments (single-`pqOwner` model, old payload layouts) and exists only so already-deployed v0 wallets remain operable. Its method names and codec offsets do **not** match the v1 contract ABI — using it against a v1 wallet produces malformed payloads. All new integrations must import from `@quip.network/ethereum-sdk/v1`.

---

## Mental model

A Quip wallet is governed by a hierarchy of WOTS+ post-quantum keys, all derivable from one secret.

```
quantumSecret   (per user — the only off-chain backup target)
    │
    └── vaultId   (per wallet — many wallets per user)
              │
              └── publicSeed   (per key — published on chain)
                        │
                        └── WOTSPlus.generateKeyPair(privSeed, publicSeed)
                                  privSeed = keccak256(quantumSecret) || vaultId
```

`quantumSecret` is the BIP39-mnemonic analog. Lose it and you lose the wallet. The SDK does not persist it — encryption at rest, unlock UX, and wiping on logout are the embedding application's responsibilities.

Every WOTS+ keypair is deterministic given `(quantumSecret, vaultId, publicSeed)`. `publicSeed` for every active key is readable from the wallet (`keyAt`, `getDisasterRecoveryKey`, `getOwnershipKey`). The user's backup obligation is one secret, not many.

---

## Critical invariant: every broadcast burns a key

WOTS+ is a one-time signature scheme. The moment a signature is broadcast — **even in a transaction that ultimately reverts** — the signing key is publicly compromised.

This applies to:

- Successful transactions
- Reverted transactions (calldata reaches the mempool)
- Dropped transactions (broadcast then evicted before mining)
- UserOps that fail wallet- or paymaster-side validation (signature still lands in the public mempool)

The SDK does **not** own a burn set. Every `QuipSigner` is constructed with a `ConsumeKeyFn` supplied by the caller:

```ts
import { QuipSigner, createInMemoryBurnSet } from "@quip.network/ethereum-sdk";

const burnSet = createInMemoryBurnSet();           // dev default
const signer = new QuipSigner(quantumSecret, burnSet.consume);
```

`consume(publicSeed)` is an atomic check-and-claim: throws `KeyAlreadyBurnedError` if the seed has already been claimed, otherwise records the claim and returns. The SDK invokes `consume(seed)` once at the top of every `signer.sign(...)` — **before** the WOTS+ signature is produced. This means a key is committed as burned the moment a sign call begins, not at broadcast time, which prevents the failure mode where a caller signs, aborts before broadcast, and a later sign call reuses the key on a different message (the actual WOTS+ violation).

Custom `ConsumeKeyFn` implementations MUST normalize the seed before comparison — `0xABCD…` and `0xabcd…` represent the same key. `createInMemoryBurnSet()` lowercases on the way in; back-end stores (sqlite, redis) need to do the same.

The SDK ships `createInMemoryBurnSet()` as the process-local default. **Production callers must back `consume` with durable storage** (sqlite, redis, IndexedDB, etc.) — a process restart that loses the burn record can resurrect a key the operator already used. Wrap `createInMemoryBurnSet()` to add disk-side effects, or write your own `ConsumeKeyFn` against your storage backend; the SDK does not care which.

> ⚠️ **`InMemoryBurnSet.clear()` is test-only.** The interface exposes a `clear()` method that drops every recorded burn. **Never call it from production code.** Once a key is broadcast, it is publicly compromised regardless of what the local burn store says — clearing the record does not unburn the key, it only re-opens the door to silently signing a second payload with the same key. Use it only in unit/integration tests that re-seed signer state between cases.

**Implication for retries.** If a write reverts or simulates against a stale head, retry MUST use a different transaction key. Pass `signWithKey: WinternitzAddress` to choose one explicitly from `getKeyset(Transaction)`. There is no in-SDK key-selection logic beyond head + explicit.

---

## Clients are bound to one (chain, account) — recreate on switch

`QuipClient`, `QuipWalletClient`, and `QuipPaymasterClient` each capture a `(chainId, account)` pair at construction/`initialize()` and **never follow the provider** when the user switches network or account afterwards. This is the wagmi/viem convention: the embedding app owns provider reactivity (it is already listening to `chainChanged`/`accountsChanged` for its UI); the SDK client is an immutable value object.

The SDK enforces the binding rather than trusting it. Every write — and every signing surface, including `signExecuteUserOp`, `signErc1271`, and `sponsorUserOp` — re-reads the provider's live chain (and, for EOA-submitted writes, its available accounts) **before any WOTS+ signature is produced**, and throws on divergence:

- `ChainChangedError` (`code: "CHAIN_CHANGED"`) — the provider is on a different chain than the client was constructed for.
- `AccountChangedError` (`code: "ACCOUNT_CHANGED"`) — the provider no longer exposes the bound account.

The pre-sign placement is deliberate: keys burn at sign time (see above), so a stale provider caught any later — by viem's chain assertion or by the provider rejecting the `from` — would already have cost a one-time key. Catch these errors, and recover by constructing a new client against the switched provider. Do not retry the same call in a loop.

Two deliberate exceptions to the snapshot rule:

- `QuipClient.getVaults()` re-resolves the provider's **active account on every call** — a read should reflect reality, not return the previous account's vault list after a switch.
- Writes also pass the bound chain to viem (instead of `chain: null`), re-enabling viem's built-in chain-consistency assertion as a backstop behind the SDK's own pre-sign check.

---

## Two execution paths, same invariant

The on-chain consequence of a revert differs depending on which path the write took:

| Path | Validation runs | Inner call reverts | Rotation on chain |
|---|---|---|---|
| `executeWithPayload` (direct) | Inside the same tx as execution | Whole tx reverts | **Not** committed |
| `buildExecuteUserOp` (ERC-4337) | Separately from execution | Only execution call reverts | **Committed** |

In both cases the SDK records the burn via the injected `ConsumeKeyFn` at sign time. In the direct path, on-chain `keyAt(Transaction, 0)` still points at the burned key — so an external observer of the failed tx could attempt to forge a sig before you rotate. Don't reuse keys after broadcast.

---

## Key-derivation self-test

Every `QuipSigner.generateKeyPair(...)` and `recoverKeyPair(...)` runs a local sign + verify against a fixed sentinel digest before handing back the keypair. Catches WOTS+ library bugs, memory corruption, or silent derivation drift before the key is ever used to sign a real payload. On mismatch the call throws `KeyDerivationSelfTestError`.

The sentinel signature is produced via the raw WOTSPlus path (bypassing `consume`), held only in a stack-local, and discarded. It never crosses the SDK boundary and is never recorded against the burn set — WOTS+ one-time-use is preserved, and the key remains usable for one real signature afterwards.

---

## Concurrency model

Multiple in-flight writes can race. WOTS+ requires each in-flight op sign with a distinct key. The SDK offers exactly two paths:

- **Default** — sign with `keyAt(Transaction, 0)` (the on-chain head). Safe for single-threaded flows. Unsafe under concurrent submission: every in-flight op would pick the same head, and the second `consume(seed)` would throw `KeyAlreadyBurnedError`.
- **`signWithKey: WinternitzAddress`** — sign with this exact key. Must be a member of the transaction keyset on chain; pre-flight `isKey(Transaction, ...)` throws `UnknownKeyError` synchronously if it has rotated out.

For concurrent writes, the caller is responsible for picking distinct keys: read `getKeyset(Transaction)`, pick keys your own burn store has not yet marked, and pass each via `signWithKey`. The SDK does not walk keysets or auto-allocate.

---

## What the SDK does NOT guarantee

- **At-rest secret encryption.** `QuipSigner` holds the `quantumSecret` in memory. Encryption, passphrase unlock, and lock timeouts are the embedding application's job.
- **Burn-set persistence.** The SDK requires a `ConsumeKeyFn` but does not own its backing store. `createInMemoryBurnSet()` is process-local and loses every burn on restart — production callers MUST wrap it (or write their own `ConsumeKeyFn`) against durable storage. Without persistence, a process restart followed by reading the on-chain head can lead to key reuse if the head still points at a key whose signature was previously broadcast.
- **Mempool drop detection.** If a broadcast tx is dropped before mining, the SDK cannot know. The burn is conservative: once a `sign()` succeeds, the key is considered dead.
- **Nonce coordination across `QuipWalletClient` instances.** Each instance manages its own writes. Don't run two clients against the same EOA + chain.
- **Cross-process or cross-device sync.** A second signer instance on another machine has no awareness of the first's burn store, unless both `ConsumeKeyFn`s point at the same durable backend.
- **In-SDK key allocation for concurrent writes.** Callers running multiple ops in parallel must pick distinct keys themselves and pass each via `signWithKey`. The SDK has no `'next-available'` walk.
- **Full signer-ownership verification.** `QuipClient.getVault` checks only that the supplied `QuipSigner` can regenerate the head transaction key (`keyAt(Transaction, 0)`). It does **not** verify ownership of every key in the wallet. A wallet operated concurrently by multiple signers, or one whose head rotated to a key only some signers know, can still produce `InvalidSignerError` for a co-signer — or, conversely, pass the check for a signer that only controls one key. Callers needing strict verification should fetch `getKeyset(Transaction)` after construction and validate each entry against `quipSigner.recoverKeyPair(...)`.

---

## Components

| Class | Role | Lifetime |
|---|---|---|
| `QuipSigner` | Holds `quantumSecret`, derives keypairs, delegates burn-tracking to an injected `ConsumeKeyFn`. | Session-scoped. One per user, per process. |
| `ConsumeKeyFn` / `createInMemoryBurnSet()` | Caller-owned WOTS+ burn store. SDK invokes it once per sign. | Caller's choice — typically process-wide and backed by durable storage. |
| `QuipWalletClient` | Orchestrates one wallet: reads, writes, simulation. | One per wallet, per process. References a `QuipSigner`. |
| `QuipClient` | Factory client: creates wallets, lists vaults, vets implementations. | One per chain. |
| `QuipPaymasterClient` | Per-wallet WOTS+ paymaster: registration, deposits, sponsored UserOp signing. | One per paymaster instance. |

---

## Error model

Every contract revert maps to a typed `QuipError` subclass — `InvalidSignatureError`, `KeyInUseError`, `InsufficientBalanceError`, etc. SDK-operational errors (`WalletNotInitializedError`, `KeyAlreadyBurnedError`, `KeyDerivationSelfTestError`, `PartialMulticallResultError`, ...) follow the same hierarchy.

No catch-all `try { ... } catch (e) { throw new Error(...) }` exists in the SDK. Unknown errors bubble untyped so callers can still see them.

Contract reverts during pre-flight surface as the decoded typed `QuipError` directly (e.g. `FeeExceedsMaxError`, `InvalidSignatureError`) — there is no wrapper class. `GasEstimationError` is thrown only when `eth_estimateGas` fails for a *non-revert* reason (network, malformed call, no code at address). Pre-flight runs through `estimateContractGas`, which executes the call via `eth_call` semantics on the node, so the revert decoding fidelity matches what a separate `simulateContract` round-trip would have given.

---

## Transaction options

Every write accepts `TxOptions & TransactionKeyOptions`:

```ts
interface TxOptions {
  gas?: bigint;                    // explicit gas override (skips estimation)
  gasMultiplier?: number;          // default 1.2, clamped to [1.0, 2.0]
  maxFeePerGas?: bigint;           // EIP-1559 override
  maxPriorityFeePerGas?: bigint;   // EIP-1559 override
  gasPrice?: bigint;               // legacy override
  nonce?: number;
  skipPreflightChecks?: boolean;   // bypass balance preflight
}

interface TransactionKeyOptions {
  signWithKey?: WinternitzAddress;   // explicit key; default is keyAt(Transaction, 0)
}
```

Defaults: balance preflight on, `gasMultiplier: 1.2` (20% buffer), EIP-1559 fees auto-detected, sign with the head transaction key. If the head is already in the burn set, the signer's `consume` throws `KeyAlreadyBurnedError` — retry with `signWithKey` pinned to a different keyset entry.

---

## Codec / client split

`wotsCodec.ts` contains every byte-level operation that mirrors a Solidity codec function — encoders, decoders, digests, hashes, domain tags. It has no I/O and no secrets.

`walletClient.ts`, `factoryClient.ts`, and `paymasterClient.ts` orchestrate I/O (RPC reads, simulation, broadcast), signing (`QuipSigner`), and policy (key allocation, retry semantics). They never re-implement byte operations.

To verify a payload off-chain or build one for a custom flow, import the codec directly:

```ts
import { WotsCodec } from "@quip.network/ethereum-sdk";
```

---

## ERC-4337

Quip wallets validate UserOps natively (`validateUserOp` → WOTS+ verify + key rotation). The SDK exposes:

- `QuipWalletClient.buildExecuteUserOp(target, value, data, opts)` — returns `{ userOp, walletDigest, userOpHash, currentKey, nextKey, executeFee }`, wallet-signed, with empty `paymasterAndData` by default
- `QuipWalletClient.buildExecuteBatchUserOp(calls, opts)` — same shape, inner call is `executeBatch(Call[])`
- `QuipWalletClient.buildDelegateExecuteUserOp(delegate, data, opts)` — inner call is `delegateExecute`; guarded slots snapshotted pre/post
- `QuipWalletClient.buildStorageStoreUserOp(slot, value, opts)` — inner call is raw `SSTORE`; rejects guarded slots
- `QuipWalletClient.simulateUserOp(userOp)` — state-override `eth_call` against `validateUserOp`; returns wallet-side validation result, paymaster-side result (when a paymaster is attached), and the unpacked `validationData` (validUntil / validAfter / authorizer) for each side
- `QuipPaymasterClient.signPaymasterUserOp(...)` and helpers to populate `paymasterAndData`

The canonical v0.7 EntryPoint address (`0x0000000071727De22E5E9d8BAf0edAc6f37da032`) is the default per-chain in `addresses.ts`; override per-chain when targeting alternate deployments.

> **`opts.entryPoint` override on `prepareExecuteUserOp` / `simulateUserOp` is test-only.** The wallet's `entryPoint()` is set at construction and is immutable. Pointing the SDK at a different EntryPoint for `userOpHash` computation produces a userOp that the wallet will reject at on-chain validation. The override exists for forking tests against alt-EntryPoint deployments; production callers should always let the SDK read `wallet.entryPoint()` (the default).

A reverted UserOp execution still **commits** the wallet's key rotation (the EntryPoint runs validation and execution as separate top-level calls). The SDK records the burn via the injected `ConsumeKeyFn` at sign time, in both cases.

`prepareExecuteUserOp` (and `buildExecuteUserOp`, which composes prepare + sign) pre-flights the inner `wallet.execute(target, value, data)` call via `eth_estimateGas` from the EntryPoint. Reverts surface as typed errors (`QuipError` subclasses for known selectors, `UnknownContractError` for non-Quip ABIs, `GasEstimationError` for bare reverts) **before any key is burned**. The other three builders (`buildExecuteBatchUserOp`, `buildDelegateExecuteUserOp`, `buildStorageStoreUserOp`) use the same pre-flight pipeline against their respective inner calldata. To bypass pre-flight on the rare "ship a userOp whose inner call I expect to revert" path, pin `opts.callGasLimit` and set `opts.skipGasEstimation: true`.

---

## SHRINCS wallets (`/v1/shrincs`)

`ShrincsWalletClient` (import from `@quip.network/ethereum-sdk/v1/shrincs`) operates the SHRINCS hash-based wallet family. The mental model differs from WOTS+ in two ways that change how you must sequence operations:

**One-time leaves, budgeted.** Normal actions sign with a stateful leaf (`leaf index = authPath.length`), each usable once per key epoch, bounded by `maxSignatures`. The client picks the lowest unused leaf automatically by reading the on-chain bitmap. Rotate before the budget exhausts (`rotateKey`); break-glass recovery (`recoverWallet`) uses the stateless half.

**Strict signing-order serialization.** Every signed context binds the wallet's live `actionNonce()`, and every consumed signature advances it. One outstanding signed authorization at a time: sign → land → sign. Signing a second op before the first lands binds a stale nonce and is rejected (`AA24` on the 4337 path; `InvalidSignatureError` on the direct path, leaf preserved). The flip side is free mass-cancellation: landing any action (even an empty `execute`) invalidates all outstanding signed material, including ERC-1271 blobs — integrators sign 1271 blobs late and re-sign after any wallet action.

### Execute fee: signed `maxFee` ceiling, live price charged

The factory charges a per-execute fee (`getExecuteFee()`). The signer authorizes a **ceiling**, not an amount:

- `execute({ target, value, data, maxFee? })` — `maxFee` defaults to the live `executeFee` read at prepare time; pass a higher value for headroom against fee increases. The wallet charges the **live** fee at landing and reverts `ExecuteFeeExceedsCapError` only if it exceeds the cap. Fee decreases succeed at the lower price and never invalidate a signature.
- On the 4337 path, `maxFee` is a required parameter of `buildExecuteUserOp` / `buildExecuteBatchUserOp` (they are pure encoders; pass `(await getWalletState()).executeFee` or headroom). It rides in `callData`, so the signature binds it via `userOpHash` — validation reads no fee at all (ERC-7562: the wallet's validation phase makes zero external calls, so conformant bundlers accept the op).
- The un-capped `execute(address,uint256,bytes)` / `executeBatch(Call[])` selectors are disabled on-chain (`StandardExecuteDisabledError`); every execution path carries a signed ceiling.

**Revert asymmetry, same as WOTS+.** A cap-exceeded revert on the **direct** path rolls back everything — leaf and nonce preserved. On the **4337** path, validation already consumed the leaf and advanced the nonce before execution reverts, so a cap-exceeded op burns the leaf without executing. Fee changes are rare owner-governance events; if in-flight exposure matters, sign with headroom.

### ERC-4337 flow

```ts
const state = await client.getWalletState();
const userOp = client.buildExecuteUserOp({
  target, value, data,
  maxFee: state.executeFee,               // the signed fee ceiling (see above)
  nonce, maxFeePerGas, maxPriorityFeePerGas, // ERC-4337 envelope
});
const { userOp: signed, userOpHash, leaf } = await client.signExecuteUserOp({ userOp, entryPoint });
// submit `signed` to your bundler; the SDK does not own bundler submission
```

`signExecuteUserOp` reads state per call (leaf, keyVersion, live `actionNonce`) and binds `userOpHash` — nothing else. Direct-path writes (`execute`, `withdrawDepositTo`, `setErc1271Key`, `rotateKey`, `upgradeToAndCall`, `transferOwnership`, `recoverWallet`) are fully synchronous: sign → simulate → broadcast → `waitForTransactionReceipt`.

---

## Versioning

`0.2.x` is a major break from `0.1.x` (see `MIGRATION.md` for the mapping). The SDK tracks the contract surface 1:1; minor releases land alongside contract upgrades that change the public surface.

### Breaking changes in `0.2.0-beta.1`

| Area | Change |
|---|---|
| `QuipClient.createWallet(vaultId, signer, keys?, opts)` | Drops the optional `keys` parameter. New signature: `createWallet(vaultId, signer, opts)`. SDK always derives all 17 initial keys from `signer.generateKeyPair(vaultId)`. |
| `QuipClient.createWalletWithImplementation(...)` | New — wraps `deploySpecificWalletProxy(index, ...)` for callers who need an older but still-vetted impl. |
| `QuipWalletClient.saveWallet(seed, keys?, opts)` | Drops the optional `keys` parameter. New signature: `saveWallet(seed, opts)`. SDK always derives the new disaster / transaction / recovery batches. |
| `QuipWalletClient.recoveryUpgradeWallet(...)` | Renamed to `recoveryUpgrade(...)`. |
| `QuipWalletClient.upgradeWallet(...)` | The `migratorPayload` option key is now `migrationPayload`. |
| `getKeyset`, `getWalletState`, `getVaults`, `getFactoryState` | The `forceSequential` option is removed. `tryMulticall` already auto-falls-back to sequential when Multicall3 isn't deployed on the chain. |
| `getNetworkAddresses(chainId)` | Now throws `UnsupportedNetworkError` for chains outside the supported set. Previously fell through to default (mainnet) addresses. Affects `QuipClient.create(...)` initialization against unknown chains. |
| `BuildExecuteUserOpResult` | Now also carries `currentKey`, `nextKey`, `executeFee`. Additive — won't break consumers reading existing fields. |
| `SimulateUserOpResult` | Now also carries `walletValidationData` and `paymasterValidationData` (unpacked `validationData` with `validUntil` / `validAfter` / `authorizer`). Additive. |
| `QuipPaymasterClient.sponsorUserOp(...)` | Now pre-flights `getPqVerifier(userOp.sender)` and throws `PqVerifierNotRegisteredError` or the new `VerifierMismatchError` **before** burning the operator's verifier key. Return shape also carries `currentVerifier` alongside `nextVerifier`. |
| `KeyType` | Single canonical export from `wotsCodec.ts`. The `walletClient.ts` export is now a re-export of the same enum (was a separate-but-numerically-identical enum object). |
| `KeyAlreadyBurnedError.message` | No longer includes the `publicSeed`; the field on the error is preserved for programmatic inspection. |

### New surface in `0.2.0-beta.1` (non-breaking)

- `QuipPaymasterClient.fromChain({ chainId, ... })` — construct against the per-chain registered paymaster.
- `QuipWalletClient.version()`, `debugIsValidSignature(hash, sig)`, `ownershipHandoverExpiresAt(addr)`.
- `QuipClient.getVettedCodeCount()`, `getVettedCodeAt(index)`, `getVettedCodeIndex(codehash)`, `getImplementationByCodehash(codehash)`, `isCodeDeprecated(codehash)`, `latestWalletImpl()`, `getPaymasterAddress()`.
- `QuipWalletClient.prepare/buildExecuteBatchUserOp`, `prepare/buildDelegateExecuteUserOp`, `prepare/buildStorageStoreUserOp` — UserOp builders for the wallet's alternate ERC-4337 inner-call paths.
