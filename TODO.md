# TODO

## Final Recourse Key (`_FINAL_RECOURSE_KEY`)

### Feature

Add a single, separately stored recovery key (`_FINAL_RECOURSE_KEY`) at a known storage slot. It can only be consumed via a dedicated `saveWallet()` function, which rotates the key on use. This key acts as the last line of defense for wallet recovery, independent of the existing `recoveryKeyHashes` set.

### Why it's required

The ERC-4337 integration introduces `delegateExecute` and `storageStore` — both allow writes to arbitrary storage. Solady's default guards protect `_OWNER_SLOT` and `_ERC1967_IMPLEMENTATION_SLOT`, and QuipWallet extends these to cover PQ storage (`quipFactory`, `pqOwner`). However, the `recoveryKeyHashes` use `EnumerableSetLib.Bytes32Set`, which spreads data across dynamically derived storage slots (array elements + internal mapping). These slots cannot be fully enumerated statically, making it impractical to guard them completely in `storageStoreGuard`, and fragile to snapshot-verify in `delegateExecuteGuard`.

Rather than attempting perfect guards over complex storage structures, the `_FINAL_RECOURSE_KEY` makes the wallet resilient to guard failure:

- Lives at a single known slot — trivially blocked by both `storageStoreGuard` and `delegateExecuteGuard`
- If recovery keys are corrupted via a buggy delegate or a missed guard, the wallet is not bricked
- Recovery keys become a convenience layer; the final recourse key is the backstop

### Open design questions

- Key type: WOTS+ (one-time, rotated on use) or a different scheme given its last-resort nature?
- Auth model: is the recourse key sufficient on its own, or does `saveWallet()` also require PQ/owner auth?
- Scope: can `saveWallet()` reset owner + pqOwner + recovery keys, or a subset?

## `mustRecover` flag for degenerate `pqOwner` states

### Problem

If `nextPqOwner` is empty (zero seed + zero hash) or equal to the current `pqOwner`, the wallet's WOTS+ security model breaks down. An empty key has a known public key hash (forgery is trivial). A repeated key violates the one-time signature property (the same key can sign again).

### Design

If either condition is detected during key rotation:

1. Set `mustRecover = true` in storage
2. Return early — do not execute the operation (no transfer, no call, no state change beyond the flag)

The `mustRecover` flag is checked at the top of every function that performs key rotation (`execute`, `changePqOwner`, `addRecoveryKeys`, `replenishRecoveryKeys`, `upgradeToAndCall`, and the ERC-4337 execution overrides). If `true`, the function refuses to proceed.

Only `recoverWallet` (or `saveWallet` / `_FINAL_RECOURSE_KEY`) can set `mustRecover` back to `false` after rotating to a valid new key.

### Storage

Add `bool mustRecover` to `WOTSPlusStorage.Layout`. Guard the slot in `storageStoreGuard` and `delegateExecuteGuard`.

## Observations

### Cross-validation key burn asymmetry

If wallet validation succeeds (key rotated) but paymaster validation fails (key NOT rotated), the wallet key is burned for an operation that never executes. The reverse is also true. Both are correct behavior per WOTS+ security — once a signature is broadcast, the key is compromised regardless. The SDK must handle this: if the op is rejected, advance to the next key for whichever side's validation succeeded.

### No sender-type validation on paymaster

The paymaster sponsors any `sender` that has a registered verifier (`setPqVerifier` is the whitelist). It does not verify the sender is actually a QuipWallet. This is acceptable because `setPqVerifier` is `onlyOwner`, so the trust boundary is at registration time. However, the paymaster could theoretically sponsor non-QuipWallet accounts if the owner registers them — this could be a feature or a footgun depending on intent. Consider whether `setPqVerifier` should enforce that the wallet is a QuipWallet proxy deployed by the factory.

## Sponsor Wallet Creation

The `QuipFactory.deployLatestWalletProxy` requires `msg.value >= creationFee`, but the EntryPoint calls `initCode` without value. To support paymaster-sponsored wallet deployment via ERC-4337 `initCode`, either:

1. Add a dedicated `createAccount(owner, salt, payload)` that waives the fee when called by the EntryPoint
2. Allow `creationFee = 0` deployments
3. Prefund the factory with the creation fee from the paymaster/relayer

Requires a factory change before fork-testing.

## Hardcode recovery key slots in `storageStoreGuard`

Precompute and hardcode the 10 `EnumerableSetLib.Bytes32Set` array element slots for `recoveryKeyHashes` in the `storageStoreGuard` override. The array length is at `base+3` (offset of `recoveryKeyHashes` in `Layout`), and each element is at `keccak256(base+3) + i` for `i = 0..9` (`MAX_RECOVERY_KEYS = 10`). Block writes to all 11 slots (length + 10 elements). This does not cover the internal mapping slots (which depend on stored values and cannot be precomputed), but protects against direct overwriting of recovery key data via `storageStore`.
