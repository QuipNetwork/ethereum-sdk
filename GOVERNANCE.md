# Governance and Trust Model

What an operator is trusted to do today, what they can't do, and where on-chain governance is heading.

---

## TL;DR

The QuipFactory and QuipPaymaster are owned by a single classical address. That owner can vet implementations, set fees, deprecate impls, withdraw factory ETH balance, and — since the factory became UUPS-upgradeable — **replace the factory's implementation** — all in a single transaction, with no on-chain timelock or staged approval. Wallet user funds are **not** at risk from a compromised factory owner; the blast radius is implementation policy, fee economics, accumulated factory revenue, and (via upgrade) denial-of-service on factory-mediated wallet flows.

The intended production posture is: factory owner is a multisig (Safe or equivalent), and eventually that multisig is itself replaced by a governance contract with a timelock. Both transitions happen via the existing `transferOwnership` flow on each contract.

---

## What the factory owner can do

Every entry in this table is `onlyOwner`, single transaction, immediate effect:

| Action | Contract / line | Effect |
|---|---|---|
| `vetImplementation(address)` | `QuipFactory.sol:86` | Adds a codehash to the vetted set. New wallets via `deployLatestWalletProxy` will use the newly-vetted impl; existing wallets can upgrade to it. |
| `deprecateImplementation(address)` | `QuipFactory.sol:116` | Marks a vetted codehash deprecated. Stops new deployments + new upgrades to that impl. |
| `undeprecateImplementation(address)` | `QuipFactory.sol:99` | Reverses a deprecation. |
| `setCreationFee(uint256)` | `QuipFactory.sol:149` | Changes the per-wallet creation fee, bounded by the immutable `MAX_FEE`. |
| `setExecuteFee(uint256)` | `QuipFactory.sol:157` | Changes the per-execute fee, bounded by `MAX_FEE`. |
| `withdraw(uint256)` | `QuipFactory.sol` | Transfers up to the factory balance to the owner. Drains accumulated fee revenue. |
| `upgradeToAndCall(address,bytes)` | Solady `UUPSUpgradeable` | Replaces the factory implementation behind the ERC-1967 proxy. THE trust-delta action — see below. |
| `transferOwnership(address)` | Solady `Ownable` | Hands ownership to a new address IMMEDIATELY. The two-step alternative is Solady's handover: the candidate calls `requestOwnershipHandover()`, the owner calls `completeOwnershipHandover(candidate)`. |

Paymaster owner has the same shape of powers over the paymasters (sponsorship config, deposit management). Note the WOTS+-family `QuipPaymaster` is sunset — source under `contracts/deprecated/QuipPaymaster.sol`, still live on chain and fully functional — while `ShrincsPaymaster` is the go-forward paymaster; see each contract for its per-method list.

## What the factory owner cannot do

Even a fully compromised factory owner key cannot:

- **Steal user funds out of any wallet.** Wallets are PQ-owned and protected by WOTS+ one-time signatures. The factory is invoked only at deploy time and as a callback receiver for the registry update on `transferOwnership`. Nothing in the factory can move funds from a wallet.
- **Forge a vetted impl.** `vetImplementation` records `impl.codehash` and asserts non-zero code. To weaponize this an attacker still has to deploy malicious bytecode and convince *users* to deploy or upgrade against it — vetting alone doesn't migrate any existing wallet.
- **Upgrade existing wallets unilaterally.** Each wallet upgrades through its own UUPS-style flow gated by the wallet's PQ owner. The factory's vetted set controls *what is upgradeable to*, not *whether an upgrade happens*.
- **Renounce ownership.** `renounceOwnership` is overridden to revert. This is invariant §12.
- **Exceed `MAX_FEE` without an upgrade.** Both fee setters revert on `newFee > MAX_FEE`. `MAX_FEE` is a per-implementation immutable, so within one implementation the cap is fixed — but a factory upgrade can install an implementation with a higher cap. The load-bearing bound is wallet-side: every wallet signs the fee (`maxFee`) into its execute digest, so no factory state can raise what a wallet actually pays (invariant §8).

### The upgrade trust delta

`upgradeToAndCall` extends the owner's power beyond curation and fees. A malicious factory implementation could: rewrite `updateWalletOwner` (every wallet's PQ ownership transfer reverts at its tail callback — denial of service, not theft), rewrite the vetted-set views (`getVettedCodeIndex`/`deprecatedImpls` — wallet upgrades brick), lift `MAX_FEE`, or corrupt registry views (UI-level; invariant §16's consequence). It still cannot force a wallet upgrade, move wallet funds, or mutate any wallet's `owner()` — those require each wallet's own PQ signature. Full analysis: [INVARIANTS.md §22](INVARIANTS.md) and [FACTORY_UPGRADEABILITY.md](FACTORY_UPGRADEABILITY.md).

So the blast radius of a single compromised owner key is: rogue impl entering the vetted set (users who blindly deploy from `latestWalletImpl` get the rogue impl), fees pushed to `MAX_FEE`, factory ETH balance drained, and — via upgrade — DoS on ownership transfers and wallet upgrades until an honest upgrade restores the logic (the proxy address, and with it the registry state, survives). Painful, recoverable, and visible — every change emits a typed event (upgrades emit ERC-1967 `Upgraded`).

## What new owners cannot be

The factory's `updateWalletOwner` callback (`QuipFactory.sol:173–201`) validates only `newOwner != 0`. The factory doesn't enforce policy on what kind of address can own a wallet — that's an out-of-band decision (cold wallet, smart account, multisig, etc.).

## Recommended operator posture

1. **Owner is a multisig.** Set `FACTORY_OWNER` and `PAYMASTER_OWNER` at deploy time to a Safe or equivalent ≥2-of-N multisig. Single-key ownership is acceptable only for testnets.
2. **Monitor sensitive events.** Off-chain monitoring on:
   - `ImplementationVetted(address impl, bytes32 codehash)`
   - `ImplementationSunset(address impl, bytes32 codehash)`
   - `ImplementationUndeprecated(address impl, bytes32 codehash)`
   - `CreationFeeUpdated(uint256 oldFee, uint256 newFee)`
   - `ExecuteFeeUpdated(uint256 oldFee, uint256 newFee)`
   - `Withdrawn(address to, uint256 amount)`
   - ERC-1967 `Upgraded(address implementation)` — a factory upgrade is the single highest-privilege owner action; alert, don't just log
   - Solady `OwnershipTransferred(address oldOwner, address newOwner)` and `OwnershipHandoverRequested(address pendingOwner)`
3. **Pre-publish vetting candidates.** Before `vetImplementation`, publish the impl's address + codehash + source provenance (commit hash, build settings — `deployments/bytecode/<Contract>.sol/<addr>.json` snapshots this from Foundry's `out/`). Users should be able to independently confirm the codehash off-chain before deploying against `latestWalletImpl`.
4. **Use `deploySpecificWalletProxy` for sensitive deploys.** Avoid `latestWalletImpl` if the user wants to pin a specific vetted index — defends against a same-block surprise vet.

## Roadmap: on-chain governance

The current design intentionally keeps governance off-chain so the v0.2 surface stays minimal and the policy/timelock story can be iterated based on actual production usage. The intended trajectory:

**Phase 1 (today).** Multisig as owner. All policy decisions are operator discipline + off-chain monitoring.

**Phase 2.** Timelock wrapper for sensitive actions. Two-step pattern: `pendingVetImplementation` / `finalizeVetImplementation(delay)`, same for fee setters and `withdraw`. Adds a user-visible grace window where any rogue queued action can be observed before it lands. Tracked in [TODO.md](TODO.md). This is a non-breaking change: existing `onlyOwner` entry points stay, but their bodies move to `finalizeX` with a `pendingX` queue.

**Phase 3.** Owner replaced by a governance contract — either a Quip-native one or a battle-tested external system (Compound Governor + Timelock, OZ Governor). `transferOwnership` is the migration primitive; no factory changes required. The governance contract becomes `owner()`, calls flow through its `execute` after a proposal + voting + timelock delay. At that point the factory's policy surface is fully on-chain enforceable rather than operator-discretionary.

Phases 2 and 3 are additive — each one tightens controls without invalidating the previous posture. A v0.2 deployment on Phase 1 multisig can move to Phase 2 by deploying a timelock and pointing factory ownership at it; Phase 3 swaps the timelock for a full governance contract the same way. No factory redeploy is required for either transition.

## Related invariants and docs

- [INVARIANTS.md §7 Implementation Vetting](INVARIANTS.md) — what the vetted set enforces on-chain.
- [INVARIANTS.md §12 Renounce Ownership Disabled](INVARIANTS.md) — the one ownership operation the factory does explicitly block.
- [INVARIANTS.md §15 Factory Reference Immutability](INVARIANTS.md) — properties of the factory address itself.
- [INVARIANTS.md §22 Factory Upgrade Safety](INVARIANTS.md) — UUPS + ERC-7201 rules and the upgrade trust delta.
- [FACTORY_UPGRADEABILITY.md](FACTORY_UPGRADEABILITY.md) — the design/scope record for the UUPS conversion.
- [DEPLOYMENTS.md](DEPLOYMENTS.md) — current owner addresses per chain.
- [TODO.md](TODO.md) — Phase 2 timelock + Phase 3 governance migration items.
