# QuipFactory Upgradeability — Scope

Effort 2 of the factory rework (effort 1, WOTS+ decoupling, landed on `feat/factory-rework`).
Status: **planned, not started**. This document is the scope agreement for the implementation.

## Why the factory must become upgradeable (and why now)

The factory address is permanently load-bearing in a way no other contract in the system is:

1. **Every wallet bakes it in forever.** Both families set `FACTORY` as a constructor immutable
   and store `quipFactory` in guarded storage at init. A wallet can never re-point: its
   `transferOwnership` tail MUST call back into that exact address (`updateWalletOwner`), its
   upgrade authorization reads that address's vetted set (`getVettedCodeIndex` /
   `deprecatedImpls`), and its execute fee is read from it.
2. **CREATE3 addressing.** `vaultId → wallet address` is a pure function of
   (factory address, salt) — initcode-independent. All counterfactual and cross-chain
   deterministic wallet addresses die with the factory address.
3. **The registry is unmigratable state.** `wallets`, `vaultIdOf`, `walletOwner`, `_vaultIds`,
   the vetted-code set, and accrued fees cannot be replayed into a successor without breaking
   invariant 16 (Registry Consistency) for every live wallet.

A replacement factory at a new address therefore fragments the registry across two factories,
requires maintaining the old vetted set forever (old wallets' upgrade gating), and changes every
future counterfactual address. "Redeploy" is not a viable fix path — so the *logic* must be
replaceable behind a stable address. Converting to a proxy changes the factory address, which
changes all counterfactual wallet addresses: this must land **before mainnet**, together with or
immediately after the decoupling.

## Design decisions

1. **Solady UUPS behind an ERC-1967 proxy** — same stack as `ShrincsPaymaster`
   (`Ownable` + `UUPSUpgradeable` + `Initializable` from solady). No OZ mix-in.
2. **ERC-7201 namespaced storage**: new `contracts/storage/QuipFactoryStorage.sol` mirroring
   `ShrincsPaymasterStorage` (library + `Layout` struct + `@custom:storage-location
   erc7201:quip.storage.factory`). All current flat declarations move in: `creationFee`,
   `executeFee`, `wallets`, `vaultIdOf`, `walletOwner`, `_vaultIds`, `_vettedCode`,
   `vettedWalletImpls`, `deprecatedImpls`, `latestWalletImpl`. `EnumerableSetLib` sets nest in
   the struct as-is.
3. **Constructor → `initialize(address initialOwner)`**; `_disableInitializers()` in the
   implementation constructor (house pattern).
4. **`MAX_FEE` stays a per-implementation immutable.** It lives in impl code, works fine behind
   a proxy, and keeps fee-cap checks at zero storage cost. Consequence to document loudly: an
   upgrade can change the cap. The wallet-side mitigation already exists — the signed `maxFee`
   in calldata bounds what any wallet ever pays regardless of factory state (invariant 8 / the
   ERC-7562 fee work). INVARIANTS.md §8 and §15 get amended accordingly.
5. **Ownership: solady `Ownable` with its two-step handover left ENABLED** (unlike the wallets,
   which disable it). Renounce stays disabled. The owner is expected to be a Quip wallet (same
   posture as the paymaster) — upgrade authorization is `_authorizeUpgrade` + `onlyOwner`, and
   the call is PQ-secured upstream by the owning wallet. A timelock on `_authorizeUpgrade` is
   explicitly out of scope for v1 but the decision is recorded as revisitable.
6. **Proxy deployed via `Deployer` (CREATE3)** so the factory proxy address is chain-invariant.
   The implementation address may differ per chain; only the proxy address matters.
7. **CREATE3-behind-proxy determinism**: solady's `CREATE3.deployDeterministic` derives from
   `address(this)` — behind the proxy that is the proxy address, so wallet addresses stay
   deterministic, chain-invariant, and (usefully) stable across factory upgrades. Must be
   pinned by a test.
8. **ERC-4337 note (informational):** if the factory is ever used as a 4337 `initCode` factory,
   it reads/writes its own storage during account creation and must be staked; that obligation
   attaches to the proxy address and is unchanged by this work.

## Trust delta (to be documented in GOVERNANCE.md + INVARIANTS.md)

Today the factory owner's power is: curation (vet/deprecate/undeprecate), fees up to an
immutable `MAX_FEE`, and treasury withdrawal. Upgrade power adds the ability to:

- rewrite `updateWalletOwner` → DoS every wallet's ownership transfer (the tail callback
  reverts);
- rewrite the vetted-set views → DoS wallet upgrades (`getVettedCodeIndex` gating);
- lift `MAX_FEE` in a new implementation (bounded wallet-side by signed `maxFee`);
- corrupt registry views (UI-level, per invariant 16's bounded consequence).

It notably does NOT add: forcing a wallet upgrade (still requires the wallet's own PQ
signature), moving wallet funds, or mutating any wallet's `owner()`. Mitigations: owner is a PQ
wallet; two-step handover; upgrade events; (future option) timelock.

## Invariant updates required

- **§15 Factory Immutability**: retitle/qualify — the wallet's *reference* to the factory stays
  immutable; the factory's *logic* becomes upgradeable behind a stable address. State the new
  pairing: stable proxy address + ERC-7201 layout discipline across upgrades.
- **§8 Fee Bounding**: note `MAX_FEE` is per-implementation and upgrade-changeable; the signed
  `maxFee` is the wallet-side floor of protection.
- New invariant: **factory storage layout continuity** — upgrades never move/retype the
  `Layout` struct fields (append-only), never re-namespace the ERC-7201 slot, and never write
  the registry outside the existing mutation paths.

## Staged plan (house workflow: report + permission gate after each stage)

1. **Solidity implementation** — `QuipFactoryStorage.sol`; convert `QuipFactory` to
   solady UUPS + Ownable + Initializable; `initialize`; `_authorizeUpgrade` (onlyOwner);
   keep every external signature byte-identical (interface `IQuipFactory` unchanged apart
   from added init/upgrade surface); deploy-script updates (`Deployer` + ERC-1967 proxy).
2. **Solidity tests** — behaviors: initialize-once, upgrade auth (owner/non-owner), storage
   continuity across a mock V2 upgrade, CREATE3 address stability across upgrade (decision 7),
   two-step handover, full-suite regression; update `DeployAll.t.sol` and integration bases to
   the proxy deployment shape.
3. **SDK implementation** — fixture/deploy-path updates (proxy deployment in `anvilFixture` /
   `shrincsAnvilFixture` and any address-derivation helpers); `copy-abi` regen; no client API
   changes expected (clients talk to the proxy address).
4. **SDK tests** — fixture-driven suites re-run; add a smoke assertion that a wallet deployed
   pre-upgrade keeps working post-upgrade (callback + fee paths) against a V2 mock.
5. **Docs** — INVARIANTS.md edits above; GOVERNANCE.md trust-delta section; README deploy-flow
   updates (steps 2/4 reference the proxy); DEPLOYMENTS.md shape for proxy+impl pairs.

## Open questions (resolve at stage 1 kickoff)

- Keep `Ownable2Step`-equivalent semantics via solady handover only, or forbid handover and
  require explicit `transferOwnership` from the owning wallet? (Current lean: allow handover.)
- Does anything on testnets depend on the current factory address? (If yes, note the
  counterfactual-address break in DEPLOYMENTS.md when the proxy lands.)
