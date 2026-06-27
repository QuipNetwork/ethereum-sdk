# System Invariants

Critical invariants that must hold across all contracts. Violating any single invariant compromises post-quantum security or financial safety.

---

## 1. PQ Key Rotation After Every Guarded Call

**After every single call guarded by a WOTS+ signature, the PQ owner key MUST be rotated.**

WOTS+ is a one-time signature scheme. Revealing a signature exposes enough information that an attacker can forge future signatures under the same key. Key rotation is not optional cleanup — it is a security-critical step that must succeed atomically with (or before) the guarded operation.

**Contracts:** QuipWallet, QuipPaymaster

**Guarded operations that rotate:**
- `changePqOwner` — rotates to caller-supplied nextPqOwner
- `execute` — rotates before/during execution
- `withdrawDepositTo` — rotates before withdrawal
- `recoverWallet` — rotates to new pqOwner chosen by recovery key holder
- `addRecoveryKeys` — rotates before key addition
- `replenishRecoveryKeys` — rotates before key replacement
- `upgradeToAndCall` — rotates before upgrade
- ERC-4337 `_validateSignature` — rotates during validation phase (before execution phase)

**ERC-4337 critical detail:** Key rotation happens in `_validateSignature`, which the EntryPoint calls during the validation phase — a separate top-level call from the execution phase. This means the key is rotated even if the user operation's execution reverts. If rotation were deferred to execution, a reverted operation would leave the revealed key in place, allowing replay.

**Violation consequence:** Signature replay. The same one-time signature can authorize arbitrary operations under the unreplaced key.

---

## 2. Key Reuse Prevention

**`nextPqOwner` must differ from the current `pqOwner` on every rotation.**

Checked via `_enforceDifferentPqOwner`: both `publicSeed` and `publicKeyHash` are compared. If either pair matches, the rotation is rejected with `PqOwnerReuse`.

Both components must differ — checking only one would allow an attacker to submit a key that shares one component, weakening domain separation.

**Contracts:** QuipWallet

**Violation consequence:** WOTS+ security is fundamentally broken when a key pair is used more than once. An attacker observing two signatures under the same key can forge arbitrary signatures.

---

## 3. Digest Domain Separation

**Every signature must be computed over a digest that binds it to a specific operation type, chain, wallet, and key pair.**

Each operation uses a unique domain tag:

| Tag | Operations |
|-----|-----------|
| `KEY_ROTATION_TAG` | changePqOwner, recoverWallet |
| `EXECUTE_TAG` | execute(bytes) |
| `KEY_MGMT_TAG` | addRecoveryKeys, replenishRecoveryKeys |
| `UPGRADE_TAG` | upgradeToAndCall |
| `VERIFICATION_TAG` | verifyUpgrade (nested) |
| `UPGRADE_RECOVERY_TAG` | recoveryUpgrade |
| `ERC4337_EXECUTE_TAG` | ERC-4337 user operations |
| `WITHDRAW_DEPOSIT_TAG` | withdrawDepositTo |
| `_PAYMASTER_APPROVE_TAG` | Paymaster sponsorship |

Every digest includes: domain tag + `block.chainid` + wallet address + current pqOwner (seed + hash) + next pqOwner (seed + hash) + operation-specific fields.

**Contracts:** WOTSPlusCodec, QuipWallet, QuipPaymaster

**Violation consequence:** Removing any component enables replay across that dimension — cross-chain, cross-wallet, or cross-operation.

---

## 4. Single Initialization

**A wallet must be initialized exactly once, and only by its factory.**

- `initializer` modifier prevents re-entry
- Only `FACTORY` address can call `initialize`
- `_verifyInitialState` asserts all post-init state is valid:
  - `quipFactory != address(0)`
  - `ownershipKey.publicSeed != 0` and `ownershipKey.publicKeyHash != 0`
  - `disasterRecoveryKey.publicSeed != 0` and `disasterRecoveryKey.publicKeyHash != 0`
  - `transactionKeys.length() == MAX_KEYS` (exactly 10)
  - `recoveryKeys.length() == MAX_KEYS` (exactly 10)
  - `verificationKeys.length() == MAX_KEYS` (exactly 10)

**Contracts:** QuipWallet

**Violation consequence:** Re-initialization resets all PQ-protected state, giving the attacker full control.

---

## 5. Always-10 Keyset Invariant (Transaction / Recovery / Verification)

**Every keyset — `transactionKeys`, `recoveryKeys`, `verificationKeys` — must hold exactly `MAX_KEYS` (10) entries at every state-transition boundary. All entries must be non-zero and unique within each set; no two keys may collide across sets.**

- `_installInitialKeys` (used by `initialize` and `migrate`) verifies each batch is exactly `MAX_KEYS`, every key has `publicSeed != 0` and `publicKeyHash != 0`, and adds via `_safeAddKey` (which calls `_enforceUnspentKey`)
- Keys stored as `keccak256(publicSeed, publicKeyHash)` hashes in an `EnumerableWinternitzAddressSet`
- Duplicate hashes within a set are rejected by the set's `add` with `KeyInUse`; cross-set collisions are rejected via the global `isKeySpent` burn index
- The four state-transition primitives all preserve the invariant:
  - `initialize` / `migrate` install all three keysets at MAX_KEYS in one signed call (init payload: 2048 bytes)
  - `saveWallet` clears and reinstalls all three keysets at MAX_KEYS (payload: 4192 bytes), authorized by the disaster-recovery key
  - `transferOwnership` clears and reinstalls all three keysets at MAX_KEYS (payload: 4288 bytes), authorized by the ownership key
  - `resetKeyset(kind, …)` clears one named keyset and reinstalls MAX_KEYS entries in one signed call
  - `replaceKeys(kind, …)` swaps N keys in/out within a single keyset without changing its size (N preserves the always-10 invariant by construction)
- Per-transaction-key rotations (`execute`, `withdrawDepositTo`, `upgradeToAndCall`, ERC-4337 validation) consume one key and install one — preserving the count

**Contracts:** QuipWallet, WOTSPlusCodec

**Violation consequence:** Duplicate keys reduce effective authorization paths. Zero-valued keys break verification. A keyset below capacity admits future operations under stale assumptions about distinct material; above capacity is structurally impossible because every install path is gated by `_safeAddKey`'s MAX_KEYS bound.

---

## 6. Storage Slot Protection

**Critical storage slots cannot be written via `storageStore` or modified during `delegateExecute`.**

Protected slots:
- `_OWNER_SLOT` (classical owner)
- `_ERC1967_IMPLEMENTATION_SLOT` (UUPS proxy pointer)
- `_PQ_FACTORY_SLOT`, `_PQ_OWNER_SEED_SLOT`, `_PQ_OWNER_HASH_SLOT` (PQ state)

`storageStoreGuard` reverts if any write targets a protected slot. `delegateExecuteGuard` snapshots all protected slots before a delegatecall and asserts they are unchanged after.

**Contracts:** QuipWallet

**Violation consequence:** A malicious delegatecall target could overwrite pqOwner, hijack the proxy, or change ownership.

---

## 7. Implementation Vetting

**Only factory-vetted, non-deprecated implementations can be deployed to or upgraded to.**

- Implementations stored by codehash in `_vettedCode` set
- Each codehash maps to an implementation address in `vettedWalletImpls`
- `deprecatedImpls` flag prevents use of known-bad implementations
- Both `upgradeToAndCall` and `recoveryUpgrade` verify the target is vetted and not deprecated
- A `verifyUpgrade` delegatecall to the new implementation provides scheme-specific validation

**Contracts:** QuipFactory, QuipWallet

**Violation consequence:** Upgrading to unvetted code means arbitrary code execution with wallet storage and balance.

---

## 8. Fee Bounding and Digest Inclusion

**Fees are capped at `MAX_FEE` and committed in the signed digest.**

- Factory owner sets `executeFee` and `creationFee`, both capped by immutable `MAX_FEE`
- The fee value is included in the execute digest — the signer explicitly authorizes the fee amount
- Fee transfer happens after successful execution (atomic with the call)

**Contracts:** QuipFactory, QuipWallet

**Violation consequence:** Uncapped fees let the factory owner drain wallets. Excluding fees from the digest lets the factory owner raise fees after signing, stealing value.

---

## 9. Upgrade Context Guard (EIP-1153)

**`migrate` can only be called within an active `upgradeToAndCall` context.**

Uses EIP-1153 transient storage:
1. `upgradeToAndCall` sets transient guard slot to 1
2. Delegatecalls `migrate` on the new implementation
3. `migrate` checks guard is non-zero; reverts otherwise
4. Guard cleared to 0 after migration

Transient storage is automatically cleared at end of transaction, preventing stale state.

**Contracts:** QuipWallet

**Violation consequence:** Without the guard, `migrate` could be called via delegatecall from another context, resetting keys.

---

## 10. Classical Owner / PQ Owner Separation

**Two independent authorization layers: classical owner (EOA/multisig) and post-quantum owner (WOTS+).**

- Classical owner: set once at initialization, controls admin functions, changed via `transferOwnership`
- PQ owner: rotates with every use, controls transaction execution, independent of classical owner
- Recovery keys: separate from both, one-time use, stored as hashes

Operations requiring PQ auth cannot be bypassed via classical owner alone and vice versa. Compromise of one layer does not directly compromise the other.

**Contracts:** QuipWallet

**Violation consequence:** If the two layers are conflated, a single key compromise means total loss.

---

## 11. EntryPoint Address

**Only the official ERC-4337 v0.7 EntryPoint (`0x0000000071727De22E5E9d8BAf0edAc6f37da032`) can call validation and execution methods.**

Hardcoded constant, enforced by `onlyEntryPoint` modifier inherited from the ERC-4337 base.

**Contracts:** QuipWallet, QuipPaymaster

**Violation consequence:** A malicious caller impersonating the EntryPoint could trigger validation/execution without proper bundling guarantees.

---

## 12. Renounce Ownership Disabled

**`renounceOwnership` reverts unconditionally on all contracts.**

Prevents accidental or social-engineered admin abandonment.

**Contracts:** QuipWallet, QuipFactory, QuipPaymaster

**Violation consequence:** Renouncing factory ownership disables fee changes, implementation vetting, and fund withdrawal — permanently bricking the system.

---

## 13. Recovery Key Hashing

**Recovery keys are stored as `keccak256(publicSeed, publicKeyHash)` hashes, never as raw key material.**

Uses `EfficientHashLib.hash` for gas-efficient keccak256 of two 32-byte values. Hashes are stored in an `EnumerableSetLib` set for O(1) membership testing.

**Contracts:** QuipWallet

**Violation consequence:** Storing raw keys in storage exposes key material to anyone who reads contract state, defeating the one-time property.

---

## 14. Codec Layout Correctness

**All payload encoding/decoding must follow the exact byte offsets defined in WOTSPlusCodec.**

Fixed layouts (selected):
- **Init:** 64B pqOwner + 640B (10 × 64B) recovery keys = 704B
- **Execute:** 64B nextPqOwner + 2144B sig + 32B target + 32B value + Nb data = 2272+N
- **RecoverWallet:** 64B recoveryKey + 64B newPqOwner + 2144B sig = 2272B
- **Paymaster:** 6B validUntil + 6B validAfter + 64B nextVerifier + 2144B sig = 2220B

Decoders use assembly pointer arithmetic to read exact offsets.

**Contracts:** WOTSPlusCodec

**Violation consequence:** Wrong offset reads decode incorrect keys or signatures, causing silent verification failures or — worse — false positives.

---

## 15. Factory Immutability

**Each wallet's factory reference is immutable after initialization.**

`FACTORY` is set in the constructor (immutable). `quipFactory` is stored in PQ-protected storage and guarded against writes. Only the factory can initialize the wallet.

**Contracts:** QuipWallet

**Violation consequence:** A mutable factory reference lets an attacker redirect fee transfers or bypass initialization checks.

---

## 16. Registry Consistency

**For every wallet `w` deployed by the factory:**
- **`walletOwner[w] == w.owner()`**, and
- **`_vaultIds[walletOwner[w]]` contains `vaultIdOf[w]`**.

The factory's per-owner registry tracks the wallet's CURRENT classical owner. `walletOwner[wallet]` is the factory's authoritative source of truth — the wallet does not get to assert who owned it previously. The invariant is established at deploy time (`_deployProxy` writes `vaultIdOf[wallet] = vaultId`, `walletOwner[wallet] = to`, and `_vaultIds[to].add(vaultId)` atomically) and preserved across every state-changing path:

- `transferOwnership(bytes)` on the wallet commits Solady's `_setOwner(newOwner)`, then calls `factory.updateWalletOwner(newOwner)`. The factory reads `oldOwner = walletOwner[msg.sender]` internally, sets `walletOwner[msg.sender] = newOwner`, and moves the vaultId between sets. Both `_vaultIds[oldOwner].remove(vaultId)` and `_vaultIds[newOwner].add(vaultId)` are checked for `false` return values and revert `RegistryDesync` if either fires — this should be unreachable while the invariant holds, but acts as a defense-in-depth backstop. Any revert in the callback unwinds the entire transferOwnership.
- No other path mutates `wallet.owner()`: classical `transferOwnership(address)` and the entire two-step handover surface (`requestOwnershipHandover`, `cancelOwnershipHandover`, `completeOwnershipHandover(address)`) all revert. `execute` / `executeBatch` cannot reach the owner slot. `delegateExecute` / `storageStore` would mutate it, but their guards snapshot the seven PQ-sensitive slots (owner included) pre-call and revert post-call, rolling back any attempted change.
- `updateWalletOwner` is callable only from the wallet whose vaultId it'll mutate (`msg.sender` must be in `vaultIdOf`), and requires `wallet.owner() == newOwner` to have already committed. The combination pins the callback to exactly the `transferOwnership(bytes)` tail.
- `recoveryUpgrade`, `saveWallet`, `recoverWallet`, `replaceKeys`, `resetKeyset`, `upgradeToAndCall` do not change `owner()`, so the invariant is trivially preserved across them.

The mappings `wallets[vaultId] = wallet` and `vaultIdOf[wallet] = vaultId` are write-once in `_deployProxy` and never rotate; `walletOwner[wallet]` and `_vaultIds[owner]` are the only state that rotates on transfer.

**Contracts:** QuipFactory, QuipWallet

**Violation consequence:** A desynced registry would let off-chain enumeration (e.g. `getVaults` in the SDK) miss wallets a user owns or surface wallets they don't. The on-chain `owner()` remains the source of truth for authorization, so a desync confuses UI but does not steal funds.

---

## Critical Dependencies

These invariants form a security web — they depend on each other:

1. **Key Rotation (1) + Reuse Prevention (2):** Rotation must happen AND the new key must differ. Either failing alone breaks WOTS+ security.

2. **Digest Binding (3) + Codec Layout (14):** Digests must include all components AND the codec must read correct offsets. A mismatch in either causes invalid verification or skipped checks.

3. **Storage Protection (6) + Upgrade Guard (9):** Protected slots block direct writes. The transient guard blocks out-of-context migration. Both are needed — one without the other leaves a bypass path.

4. **Vetting (7) + Initialization (4):** Only vetted code is deployed. During init, the wallet binds to its factory. Failing to vet or mismatching the factory breaks upgrade security.

5. **ERC-4337 Validation Phasing (1) + Execution Reversion:** Key rotation in the validation phase survives execution-phase reverts. Moving rotation to execution would create a window where a revealed key remains active.
