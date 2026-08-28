# Quip Ethereum SDK — Reference

`@quip.network/ethereum-sdk` is a TypeScript SDK for post-quantum-secured wallets on EVM chains. This document is the operational reference: critical invariants, architectural responsibilities, and the rules consumers must follow.

For installation and a quickstart, see the package `README.md`. This file is the "what you need to know to use this correctly" companion.

> ⚠️ **The WOTS+ wallet family is sunset.** SHRINCS (`@quip.network/ethereum-sdk/v1/shrincs`) is the go-forward family, and all new integrations must use it. Existing WOTS+ wallets stay operable through the `@quip.network/ethereum-sdk/deprecated/v0` client. See "Legacy WOTS+ wallets" below.

---

## SHRINCS wallets (`/v1/shrincs`)

`ShrincsWalletClient` (import from `@quip.network/ethereum-sdk/v1/shrincs`) operates the SHRINCS hash-based wallet family. The mental model differs from WOTS+ in two ways that change how you must sequence operations:

**One-time leaves, budgeted.** Normal actions sign with a stateful leaf (`leaf index = authPath.length`), each usable once per key epoch, bounded by `maxSignatures`. The client picks the lowest unused leaf automatically by reading the on-chain bitmap. Rotate before the budget exhausts (`rotateKey`); break-glass recovery (`recoverWallet`) uses the stateless half.

**Trees never come back.** Every key install (`rotateKey`, `recoverWallet`, `transferOwnership`, `migrate`; paymaster `rotateStatefulKey`) must present material this contract has never held: the stateful tree is identified by `keccak256(pkSeed ‖ root)` — the trailing `maxSignatures` is excluded, so re-declaring a budget does not make a new key — and the stateless tree by `keccak256(pkSeed ‖ hypertreeRoot)`. Re-installing a tree would hand it a blank leaf bitmap under a fresh epoch and resurrect every leaf it already consumed, so the contracts keep lifetime registries and revert `StatefulTreeSpentError` / `StatelessTreeSpentError`. The clients pre-flight the one case they can see — the target equals the *installed* tree — before any leaf is reserved; a cycle back to an older tree surfaces as the decoded on-chain error. Always keygen fresh material (`ShrincsCodec.statefulTreeId` / `statelessTreeId` expose the identities).

**Strict signing-order serialization.** Every signed context binds the wallet's live `actionNonce()`, and every consumed signature advances it (sole exception: `markLeavesUsed`, below). One outstanding signed authorization at a time: sign → land → sign. Signing a second op before the first lands binds a stale nonce and is rejected (`AA24` on the 4337 path; `InvalidSignatureError` on the direct path, leaf preserved). The flip side is free mass-cancellation: landing any action (even an empty `execute`) invalidates all outstanding signed material, including ERC-1271 blobs — integrators sign 1271 blobs late and re-sign after any wallet action.

### Key derivation (QUIP HD v1)

`ShrincsSigner` derives every keygen seed through the QUIP HD path — a
hardened-only, SLIP-0010-style HMAC-SHA512 chain. Hash-based HD wallets
have no external standard, so QUIP defines its own:

    m / 20814' / algorithm' / network' / account' / index'

- `20814` (`0x514E`, ASCII "QN" big-endian) marks the QUIP HD scheme.
- `algorithm` defaults to the reserved experimental identifier
  `0x7FFFFFFF`. The SHRINCS profile is pre-standard. Registered
  identifiers come later, below `0x7F000000`.
- `network` defaults to `20049` (`0x4E51`, ASCII "QN" little-endian) — the
  QUIP network chain ID. The network identifier is a fixed constant.
  It does not follow the deployment chain, so one mnemonic yields the
  same keys on every EVM chain.
- `account` defaults to `0`.
- `index` is the `derivationIndex` the wallet and paymaster clients pass.
- `index` and `account` must be integers in `[0, 2^31)` (the hardened
  index domain).

Construct a signer from a BIP-39 mnemonic or a raw seed:

    import { ShrincsSigner, generateMnemonic } from "@quip.network/ethereum-sdk/v1/shrincs";

    const mnemonic = generateMnemonic(); // 12 words; generateMnemonic(256) for 24
    const signer = await ShrincsSigner.fromMnemonic(mnemonic, { passphrase: "optional" });
    // or: await ShrincsSigner.create(rawSeedBytes)

Every level uses hardened derivation. Hash-based keys have no
parent-to-child public-key relation, so non-hardened (xpub-style)
derivation does not exist here. Seeds derived by the pre-HD keccak
scheme are not reachable through this path. Recover such keys with
`keygenFromSeedHex`.

### External verifier delegation

Since hashsigs-solidity 0.2.0, the wallet and paymaster implementations no longer inline the SHRINCS verification bytecode. Each pins the canonical deployed `SHRINCS256sKeccak` ERC-7913 verifier as an `immutable` (`getShrincsVerifier()` / `SHRINCS_VERIFIER()`), set at implementation deployment. The verifier is trustless by construction — no owner, no storage, no upgradability — so the pin grants it no authority: it can only answer "does this signature verify over this 32-byte hash". All state (leaf bitmap, action nonce, `keyVersion`, installed commitments) stays in the wallet.

How the delegation preserves the inlined library's semantics exactly:

- The verifier calls inlined at `_validateSignature`, `verifyUpgrade`, `_verifyStatefulAndConsume`, and `_checkErc1271Signature`, plus `_statelessRotate`, are the only paths to signature cryptography. Each computes the canonical message hash locally (pure `SHRINCS` helpers) and delegates everything else via a staticcall over the exact 32 hash bytes — byte-identical to the inlined check, because the ERC-7913 verifier verifies over `SPHINCSPlusC.toMessage(hash) == abi.encodePacked(hash)`, precisely what `SHRINCS.verifyStateful`/`verifyStateless` hash internally.
- The envelope is always `abi.encode(publicKey, signature)` — byte-identical to `SHRINCS.encodeStatefulEnvelope`/`encodeStatelessEnvelope`, the formats the verifier re-tags in place.
- The verifier re-runs the full bundle checks (installed-commitment match, key shape, key decode) before the crypto, so none of those are replicated wallet-side. For rotations, the wallet keeps only what the verifier can never see — the rotation *target*: `nextKey` structural validation and the declared-vs-recomputed next-commitment equality.
- The library's `validActionContext`/`validRotationContext` nonzero membranes are not replicated: every context is wallet-built from keccak-derived fields, so they can never trip — with one real exception, the caller-supplied ERC-1271 `hash`, which is zero-guarded at its call site.
- Revert model: 0.2.0 replaced the library's signature shape checks with revert-as-rejection — garbage signature *internals* (attacker-controlled array lengths inside `userOp.signature` or a 1271 blob) revert inside the verifier instead of returning `0xffffffff`, and the dep explicitly leaves the boolean policy to callers. The wallet's policy boundary is `_tryVerifyStateful`/`_tryVerifyStateless`: every verifier revert maps to "invalid signature", preserving `validateUserOp`'s never-revert-on-bad-sig property and never-revert ERC-1271. Accepted trade-off: an inner out-of-gas also reports as an invalid signature. A codeless verifier address stays loud (solc's return-data decoding error is deliberately not swallowed by try/catch) — a missing verifier is never misread as a bad signature.
- ERC-7562: the verifier is storage-free and pure-opcode, so the validation-phase staticcall is compliant (`ERC7562_COMPLIANCE.md` N-5); the trust model is invariant 19 in `INVARIANTS.md`.

### Execute fee: signed `maxFee` ceiling, live price charged

The factory charges a per-execute fee (`getExecuteFee()`). The signer authorizes a **ceiling**, not an amount:

- `execute({ target, value, data, maxFee? })` — `maxFee` defaults to the live `executeFee` read at prepare time; pass a higher value for headroom against fee increases. The wallet charges the **live** fee at landing and reverts `ExecuteFeeExceedsCapError` only if it exceeds the cap. Fee decreases succeed at the lower price and never invalidate a signature.
- On the 4337 path, `maxFee` is a required parameter of `buildExecuteUserOp` / `buildExecuteBatchUserOp` (they are pure encoders; pass `(await getWalletState()).executeFee` or headroom). It rides in `callData`, so the signature binds it via `userOpHash` — validation reads no fee at all (ERC-7562: the wallet's only validation-phase external call is the compliant staticcall to the storage-free verifier, so conformant bundlers accept the op).
- The un-capped `execute(address,uint256,bytes)` / `executeBatch(Call[])` selectors are disabled on-chain (`StandardExecuteDisabledError`); every execution path carries a signed ceiling.

**Revert asymmetry.** A cap-exceeded revert on the **direct** path rolls back everything — leaf and nonce preserved. On the **4337** path, validation already consumed the leaf and advanced the nonce before execution reverts, so a cap-exceeded op burns the leaf without executing. Fee changes are rare owner-governance events; if in-flight exposure matters, sign with headroom.

### Leaf revocation: `markLeavesUsed` (surgical)

`markLeavesUsed({ leaves })` burns target leaves in the current key epoch's bitmap, authorized by one stateful signature from a *different* leaf. Use it for OTS hygiene — a leaf whose one-time key signed a message that will never land (superseded by the nonce) must never sign a second message — or to kill one specific outstanding approval.

- **Surgical: no nonce advance.** Unlike every other landed action, revocation does not touch `actionNonce()`, so outstanding signed material at non-revoked leaves stays valid. It is the targeted complement to the empty-`execute` cancel-all.
- **Skip, don't brick.** Already-used targets (a pending action raced its own revocation, duplicates) are skipped with a `LeafRevocationSkipped` event; the batch never reverts for a race. Out-of-range targets throw `LeafOutOfRangeError` and an empty array throws `EmptyLeavesError` — both client-side before signing, and on-chain as the backstop.
- **The authorizing leaf never comes from the target set.** A leaf you are revoking has typically already signed off-chain; signing the revocation with it would be exactly the key reuse being prevented. The client auto-picks outside the set; an explicit `opts.leaf` inside it throws `AuthLeafInTargetsError` before signing. Each call costs one leaf of budget on top of the leaves it burns.

### ERC-4337 flow

```ts
const state = await client.getWalletState();
const userOp = client.buildExecuteUserOp({
  target, value, data,
  maxFee: state.executeFee,               // the signed fee ceiling (see above)
  nonce, maxFeePerGas, maxPriorityFeePerGas, // ERC-4337 envelope
});
const { userOp: signed, userOpHash, leaf } = await client.signExecuteUserOp({
  userOp, entryPoint,
  owner, // the wallet owner's LocalAccount — every userOp is hybrid-signed
});
// submit `signed` to your bundler; the SDK does not own bundler submission
```

`signExecuteUserOp` reads state per call (leaf, keyVersion, live `actionNonce`), binds `userOpHash`, and collects the owner's ECDSA co-signature. **Every userOp is hybrid**: `userOp.signature` is `abi.encode(PublicKey, StatefulSignature, bytes ecdsaSig)`, where the third field is the owner's signature over the wallet's `quipUserOpHashEcdsaTarget(userOpHash)` EIP-712 digest — the 4337 route requires BOTH the SHRINCS key and the classical owner, exactly like the `onlyOwner` direct path (INVARIANTS §24). The co-signature domain is deliberately distinct from the ERC-1271 `quipSignedHashEcdsaTarget`, so a dApp-harvested message signature can never authorize a userOp. The paymaster's sponsorship blob is unaffected (plain `(PublicKey, StatefulSignature)` pair — its admin authority is owner-fiat). Direct-path writes (`execute`, `withdrawDepositTo`, `setErc1271Key`, `rotateKey`, `markLeavesUsed`, `upgradeToAndCall`, `transferOwnership`, `recoverWallet`) are fully synchronous: sign → simulate → broadcast → `waitForTransactionReceipt`.

### Sponsorship paymaster (`ShrincsPaymasterClient`)

One global SHRINCS stateful key sponsors every wallet: the operator signs each userOp it will pay for, bound to that op's `sender` + `nonce`, so signatures can't be replayed across wallets and land in ANY order (no wrapper nonce — anti-replay is the one-time leaf). Signing order in the 4337 flow: the paymaster fills `paymasterAndData` FIRST (`sponsorUserOp`), then the wallet signs the final `userOpHash` over it.

**Admin is owner-fiat.** `rotateStatefulKey` and `markLeavesUsed` carry no PQ signature of their own — the paymaster's owner is expected to be a post-quantum wallet, which secures the admin path upstream. This is deliberate: a compromised or lost sponsorship key must never gate its own replacement.

**Rotation rotates the stateful subkey ONLY.** `rotateStatefulKey({ nextStatefulPublicKey })` takes a fresh key's encoded 68-byte stateful public key (keygen it under a NEW vaultId of the same signer) and carries the installed bundle's stateless half forward. The new `maxSignatures` budget rides inside the encoding. The client pre-flights the current keypair against the on-chain commitment (`VerifierMismatchError` before any tx).

**After a rotation, the live bundle is a cross-vault graft** — the new vault's stateful secrets under the ORIGINAL vault's stateless half. A plain `recoverKeyPair` on either vault reproduces the wrong commitment; build the operator keypair explicitly and pass it as the `keypair` constructor param:

```ts
const grafted = signer.deriveKeyPair({
  statefulVaultId: newVault,      // rotated-in stateful key
  statelessVaultId: originalVault, // stateless half never rotates
  maxSignatures: NEW_MAX,
});
const pmClient = new ShrincsPaymasterClient({ ...params, vaultId: newVault, keypair: grafted });
```

**Revocation spends budget.** `markLeavesUsed(leaves)` kills outstanding sponsorship signatures by marking their leaves used (idempotent per leaf; out-of-range reverts the batch). Every fresh mark decrements `remainingStatefulSignatures()` — a leaf is available, sponsored, or revoked, and the three always sum to the budget.


---

## Deployments (SHRINCS, V1.0.1 generation)

Every SHRINCS address is a sender-guarded CREATE3 value — identical on every chain the operator has deployed to. `getShrincsAddresses(chainId)` / `getNetworkAddresses(chainId)` return that single address set for any chain in the SDK's allowlist (Ethereum, Sepolia, Base, Base Sepolia, Optimism, OP Sepolia, MIDL) and throw `UnsupportedNetworkError` otherwise.

**Allowlisted ≠ live.** The allowlist says the addresses are *derivable* on that chain, not that contracts exist there. The SDK does not probe for code. Before binding a client to a chain, the consumer MUST confirm the deployment is live — e.g. `publicClient.getCode({ address: getNetworkAddresses(chainId).WalletFactory })` is non-empty — or expect opaque reverts from an empty address.

| Chain | Status (2026-08-27) |
|---|---|
| Base Sepolia (84532) | live |
| OP Sepolia (11155420) | live |
| Base (8453) | not deployed — awaits the V4/V3 verifier pair |
| Ethereum (1), Sepolia (11155111), Optimism (10), MIDL (777) | not deployed |

| Contract | Address |
|---|---|
| WalletFactory proxy | `0xA2B2F71456a799FCf4EF7A3111c4B96b3e928cc8` |
| ShrincsWallet implementation | `0x076bF15aa48bf12a6D9f48b3b0D79875d4E1e094` |
| ShrincsPaymaster proxy | `0x430c8c89492E3541e141148Dd7a7D6dD432e5890` |
| SHRINCS256sKeccak verifier (V4) | `0xF2f9E6D692da41b089c3c261c41509669eEc5567` |
| EntryPoint v0.7 | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |

The paymaster's sponsorship key on both testnets has commitment `0x538c6eb0aa2a22531068031057e7baac0b1d5dea46a8473bbe96c0aad4e807bf` (`maxSignatures` 4096, QUIP HD derivation index 0). Its EntryPoint deposit is not yet funded, so sponsored userOps fail with `AA31` until it is. Full salt/derivation records live in `DEPLOYMENTS.md` of the contracts repo. The previous V1.0.0 generation (factory `0xdCD90563…`) is retired; wallets created through it are not reachable from this SDK version.

---

## Legacy WOTS+ wallets (`/deprecated/v0`)

The WOTS+ wallet family is sunset. SHRINCS is the go-forward family. Existing WOTS+ wallets stay operable through the `@quip.network/ethereum-sdk/deprecated/v0` client (`QuipSigner`, `QuipWalletClient`, and `QuipClient`). This client targets the original QuipFactory and QuipWallet contracts.

A WOTS+ wallet address comes from the original QuipFactory. The factory deploys each wallet through CREATE2, so the address is a function of the factory, the vault id, and the wallet init code. Only the original QuipFactory reproduces that address, and it produces the same address on every chain that runs the factory. This keeps a WOTS+ wallet address the same across chains.

A chain whose QuipFactory address is the zero address never had the factory deployed. WOTS+ wallets were never supported there. `QuipClient` throws during initialization on such a chain instead of binding to the zero address.

The `deprecated/v0` client targets the original pre-v1 contracts. Its method names and payload layouts do not match the SHRINCS ABI. Use it only against original WOTS+ deployments.

---

## Versioning

`0.2.x` is a major break from `0.1.x` (see `MIGRATION.md` for the mapping). The SDK tracks the contract surface 1:1; minor releases land alongside contract upgrades that change the public surface.

### Breaking changes in `0.3.0-beta.6`

| Area | Change |
|---|---|
| Verifier | Contracts pin the **V4** `SHRINCS256sKeccak` verifier (hashsigs-solidity MR !26): every raw ERC-7913 signature is bound to the full public-key commitment. Signatures produced by earlier SDK versions do not verify. |
| Wasm boundary | Requires `@quip.network/hashsigs-wasm@0.2.1-rc9`. The wasm exchanges `Uint8Array` ABI envelopes; `types.ts` owns the DTO shapes and `WasmShrincsKeypair` is gone from the public surface. Signing goes through the explicit-leaf entry points; the V4 digest bindings (`statefulRawMessageHash` / `statelessRawMessageHash`) are applied inside `ShrincsKeyPair`, so callers keep signing canonical action hashes. |
| Key derivation | QUIP HD v1 (hardened SLIP-0010-style chain, see above). The same secret derives a DIFFERENT keypair than `0.3.0-beta.5` and earlier — regenerate any stored public keys / commitments. |
| Addresses | Full redeploy (V1.0.1 generation, see *Deployments*). Every contract moved, including the WalletFactory proxy, so wallet addresses derive fresh; nothing from the V1.0.0 generation carries over. Live on Base Sepolia and OP Sepolia only. |
| Hash suites | `HASH_SUITE_SHA2_256 = 2`; `HASH_SUITE_UNSUPPORTED = 0xFFFFFFFF` (V4 sentinel). |

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
