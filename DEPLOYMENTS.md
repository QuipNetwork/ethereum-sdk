# Deployments

## Live — canonical addresses (CreateX-direct, sender-guarded)

The go-forward lineage: WalletFactory (UUPS) + SHRINCS family, deployed by
`script/01_DeployFactory.s.sol` → `script/02_DeployShrincs.s.sol`. Every
address is a function of (CreateX, `DEPLOY_OPERATOR`, salt preimage) — see
`script/Constants.sol` for the salts — and is identical on every chain the
operator deploys to. Derived for the canonical operator below; verify locally
with `DEPLOY_OPERATOR=0x... make predict-addresses`.

**Live on Base Sepolia (84532) and OP Sepolia (11155420) as of 2026-07-29.**
OP Sepolia got the full stack; Base Sepolia's factory and wallet impl predate
that day (2026-07-21) and were untouched — only the paymaster pair rolled, so
both chains now run identical code at identical addresses.

| | Address |
|---|---|
| DEPLOY_OPERATOR (canonical) | `0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26` |
| WalletFactory impl | `0x738456Bc546b887764bD6C462FDA6d49bBcA0c9f` |
| **WalletFactory proxy** (permanent factory identity) | `0x6de121F7cc8b310aDBc957425B97e1C8dfcE3BE5` |
| ShrincsWallet impl | `0xb84a596A6fB567FC4634b4f49212410D1193140e` |
| ShrincsPaymaster impl | `0x71c976A2FCed1B5e9C171BAf029a12fdaf391f49` |
| **ShrincsPaymaster proxy** (canonical paymaster) | `0xd258BA8ddEACe7A74184f368B7FDb55DDa53DcC5` |
| SHRINCS256sKeccak verifier (external, pinned) | `0x9154dA0BA19600C543a8c5ed1B1c44af415B5688` |

> ⚠️ **Retired paymaster pair (V1.1).** `0xfc5b4E75CA03c260255523DbbF56e93F9cbB5c59`
> (impl) and `0xE38420930EBD214FE8FEb403dd66F4887AEF76E8` (proxy) are still live
> on Base Sepolia running the PRE-rework code, where `initialize` took a
> commitment + leaf budget directly instead of deriving them from the full
> public-key bundle. Their CREATE3 addresses are permanently occupied there, so
> the V1.1 preimages can never be redeployed — hence the roll to `V1.0.1-beta`,
> which also re-bases the paymaster onto the same `-beta` scheme the factory
> uses. Withdraw the retired proxy's EntryPoint deposit/stake; nothing should
> point at it. The wallet impl and the factory did NOT change and keep their
> addresses.

> The verifier is deployed by hashsigs-solidity's own CreateX scripts (its
> `DEPLOYMENTS.md`), not this repo — the Shrincs implementations pin it as an
> immutable, and `02_DeployShrincs` refuses to deploy unless the pinned
> address hosts the expected scheme (`PROFILE_TAG`).

## v1.1 — canonical addresses (CREATE3 via the v1 Deployer)

All v1.1 contracts share the same addresses on every chain where the v1
Deployer is bootstrapped. Live on Base Sepolia as of 2026-06-03; other
CREATE3 chains require a v1.1 deploy to materialize. Computed before any
deploy is broadcast — run `make predict-addresses` to see them locally
with no env vars and no RPC.

| Contract | Address |
|---|---|
| Deployer (v1, reused) | `0xA1A3990Ea898123e4B107D0A2f614232bE428Ef1` |
| WOTSPlus | `0x7837b85Fa4D31a5af8FD28e66b18f156F66C3723` |
| QuipFactory | `0xd175378EC511e56BbffcC802375C6ad7d892c083` |
| QuipWallet (impl) | `0xDe0Eb22871dC0F51B0C625c9a4ff9e8D1ac96d64` |
| QuipPaymaster (impl) | `0x557453653005e6F35EA3265733f3F1c4643A1627` |
| QuipPaymaster (proxy, canonical) | `0xC4209cD353CF7B1dbBf6F6B4d08bC5461aC7E145` |

> The QuipPaymaster proxy is the user-facing paymaster address; the impl
> behind it is intentionally inert (`_disableInitializers()` runs in its
> constructor).
>
> The Deployer keeps its v1 salt — bumping the contract-host's address
> would break the cross-chain pin without a corresponding redeploy
> everywhere. Only the downstream contracts roll forward.

> ⚠️ **The WOTS+ family is sunset** (July 2026). `WOTSPlus`, `QuipWallet`, and
> `QuipPaymaster` above are the deprecated WOTS+ family — the deployed artifacts
> remain live and fully functional, but the source now lives under
> `contracts/deprecated/` (deploy scripts under `script/deprecated/`; SDK surface
> under the `./deprecated/*` npm subpaths). SHRINCS (`ShrincsWallet` +
> `ShrincsPaymaster`) is the go-forward family.

> ⚠️ **The go-forward factory (UUPS, renamed `WalletFactory`) supersedes the
> address above — and deploys through a new mechanism.** The factory became
> UUPS-upgradeable (impl + ERC-1967 proxy, like the paymaster), and in July
> 2026 the contract was renamed `QuipFactory` → **`WalletFactory`** and the
> deploy path moved to **CreateX-direct with sender-guarded salts** (see
> below) on fresh `V1.0.0-beta` salts (the interim `V2` salt strings were
> never broadcast, so no deployed address was orphaned). The V1.1 salt is
> retired because CREATE3 ignores initcode, so reusing it would resolve to
> the old non-upgradeable factory on chains where it exists. The new proxy
> address (the permanent factory identity — wallets bake it in, CREATE3
> wallet addressing derives from it) is recorded in the **Live** table at the
> top of this file. The `0xd175…` V1.1 factory above remains on Base Sepolia
> as a retired artifact under its historical name.

### Salts

**Live contracts** — sender-guarded CreateX preimages. The deployed address
is a function of (CreateX, `DEPLOY_OPERATOR`, preimage); only the operator
can consume the salt. The Shrincs *implementation* preimages append
`SHRINCSParams.PROFILE_ID` (= `keccak256("shrincs-256s-keccak")`, the
verifier's `PROFILE_TAG()`) so an impl built against a different
cryptographic scheme structurally lands at a different address.

| Contract | Salt preimage |
|---|---|
| WalletFactory impl (UUPS) | `QUIP:WalletFactory:Impl:V1.0.0-beta` |
| WalletFactory proxy (canonical) | `QUIP:WalletFactory:Proxy:V1.0.0-beta` |
| ShrincsWallet impl | `QUIP:ShrincsWallet:V1.1:` ‖ `PROFILE_ID` |
| ShrincsPaymaster impl | `QUIP:ShrincsPaymaster:Impl:V1.0.1-beta:` ‖ `PROFILE_ID` |
| ShrincsPaymaster proxy | `QUIP:ShrincsPaymaster:Proxy:V1.0.1-beta` |

Each contract's salt moves only when its own bytecode does, so the wallet and
the paymaster version independently — the wallet is unchanged since its V1.1
deploy. Retired, permanently occupied on Base Sepolia (never reuse):
`QUIP:ShrincsPaymaster:Impl:V1.1:` ‖ `PROFILE_ID` and
`QUIP:ShrincsPaymaster:Proxy:V1.1`.

**Sunset WOTS+ era** — unguarded salts (`keccak256(preimage)`) consumed
through the deprecated Deployer; addresses depend only on (Deployer, salt).

| Contract | Salt preimage |
|---|---|
| Deployer (via CreateX, unchanged) | `QUIP:Deployer:V1` |
| WOTSPlus | `QUIP:WOTSPlus:V1.1` |
| QuipFactory (retired, non-upgradeable) | `QUIP:QuipFactory:V1.1` |
| QuipWallet impl | `QUIP:QuipWallet:V1.1` |
| QuipPaymaster impl | `QUIP:QuipPaymaster:Impl:V1.1` |
| QuipPaymaster proxy | `QUIP:QuipPaymaster:Proxy:V1.1` |

### CreateX-direct (live contracts)

Live contracts (`WalletFactory`, `ShrincsWallet`, `ShrincsPaymaster`)
deploy straight through the **CreateX** singleton at
`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed` (pre-deployed on every chain
via Nick's-method presigned tx) — no in-repo deploy contract, no bootstrap
step. `script/CreateXHelpers.sol` implements the scheme; the release/predict
tooling (`scripts/release.ts`, `script/PredictAddresses.s.sol`) mirrors it.

Salt scheme (CreateX's `_parseSalt` layout, MsgSender + no-crosschain mode):

```
rawSalt     = bytes20(DEPLOY_OPERATOR) ‖ 0x00 ‖ bytes11(keccak256(preimage))
guardedSalt = keccak256(bytes32(uint160(DEPLOY_OPERATOR)) ‖ rawSalt)
address     = CREATE3(CreateX, guardedSalt)
```

- **Sender-guarded (squat-proof):** the raw salt embeds the operator's
  address, so CreateX only accepts it from `msg.sender == DEPLOY_OPERATOR`.
  Nobody else can consume a canonical salt on a fresh chain. (CREATE3
  ignores initcode — under the old permissionless Deployer, anyone could
  have deployed arbitrary code at a canonical address first, and the
  idempotent skip would have silently accepted it.)
- **Chain-invariant:** the 21st byte `0x00` opts out of CreateX's chainid
  binding, so the same (operator, preimage) lands at the same address on
  every chain.
- **API asymmetry to remember:** `CreateX.deployCreate3` consumes the RAW
  salt (and guards internally); address *prediction* consumes the GUARDED
  salt — offline via solady's `CREATE3.predictDeterministicAddress(guardedSalt,
  CreateX)` (CreateX uses the same CREATE3 proxy initcode), no RPC needed.

> ⚠️ **Every live canonical address is a function of `DEPLOY_OPERATOR`.**
> The operator key must sign each canonical deploy on each chain, forever —
> losing it means losing the ability to materialize the canonical addresses
> on new chains. Guard that key accordingly.

### Deployer bootstrap (sunset WOTS+ era)

The historical flow for the WOTS+ family, kept only to reproduce the
deployed artifacts (`contracts/deprecated/Deployer.sol`,
`script/deprecated/DeployDeployer.s.sol`). The Deployer *hosts* solady
CREATE3, so it can't deploy itself — it was bootstrapped via CreateX on an
**unguarded** salt: `keccak256("QUIP:Deployer:V1")` has its first 20 bytes
as random hash output (neither `msg.sender` nor `address(0)`), so CreateX's
guard hits the fallback branch `guardedSalt = keccak256(abi.encode(salt))`.
Any funded wallet can broadcast the bootstrap, and the address is the same
on every chain — but that permissionlessness is exactly the squatting
exposure the live sender-guarded scheme closes. Once the Deployer exists on
a chain, the WOTS+-era contracts deploy through it via solady CREATE3.

### Library linking

`QuipWallet` (the sunset WOTS+ implementation, `contracts/deprecated/wots/`)
calls into the `WOTSPlus` library at runtime — its compiled
bytecode contains a placeholder that must be replaced with WOTSPlus's
address before deploy. (`WalletFactory` no longer links WOTSPlus: the
WOTS+ decoupling removed its last dependency, so factory bytecode is
link-free.) Foundry handles the wallet linking via the
`[profile.deploy]` profile in `foundry.toml`:

```toml
[profile.deploy]
libraries = [
    "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol:WOTSPlus:0x7837b85Fa4D31a5af8FD28e66b18f156F66C3723"
]
```

Only the sunset WOTS+ scripts (under `script/deprecated/`) touch
`QuipWallet` bytecode and run under `FOUNDRY_PROFILE=deploy`; the live
numbered entrypoints link no libraries and need no profile.

### Deployment workflow

The live flow is two numbered scripts, run in order (both idempotent —
re-runs skip anything already deployed/vetted):

```
0. Predict addresses     DEPLOY_OPERATOR=0x... make predict-addresses
                         # No RPC needed. Live rows require DEPLOY_OPERATOR
                         # (they are a function of it); without it only the
                         # sunset WOTS+-era rows print.

1. Deploy factory        make deploy-factory-<chain>
                         # script/01_DeployFactory.s.sol: WalletFactory impl
                         # + ERC-1967 proxy via CreateX. PRIVATE_KEY must be
                         # DEPLOY_OPERATOR's key (sender-guarded salts).
                         # Requires DEPLOY_OPERATOR, FACTORY_OWNER, MAX_FEE.

2. Deploy Shrincs        make deploy-shrincs-<chain>
                         # script/02_DeployShrincs.s.sol: ShrincsWallet impl
                         # (vetted; becomes latestWalletImpl) + ShrincsPaymaster.
                         # Locates the factory at its canonical derived address
                         # only (no env override) and verifies it is an
                         # operator-owned ERC-1967 proxy before broadcasting.
                         # Requires SHRINCS_* in .env.
```

Ops utility: `IMPLEMENTATION=0x... make vet-impl-<chain>` — the factory
owner whitelists an already-deployed wallet impl (any family; idempotent).

Sunset WOTS+ family (optional, frozen under `script/deprecated/`):
`make deploy-deployer-<chain>` bootstraps the legacy `Deployer`, then
`make deploy-impl-<chain>` deploys a WOTSPlusImplementation through it
(`FOUNDRY_PROFILE=deploy`; per-chain targets set it automatically).
Note that vetting a WOTS+ impl AFTER the Shrincs deploy would flip
`latestWalletImpl` back to WOTS+ — the intended default is Shrincs.

`<chain>` is `base-sepolia` or `op-sepolia`; see Makefile for the full list of
per-chain targets. Step 1 is a no-op on a chain whose factory is already live
(both scripts are idempotent per-contract), so rolling only the paymaster onto
an existing chain is just step 2.

### Required environment variables

Put these in a project-local `.env` (Makefile auto-loads it). All
addresses below are examples — substitute your actual operator wallets.

```bash
# Chain RPC + Etherscan
API_URL_BASE_SEPOLIA=https://base-sepolia.g.alchemy.com/v2/<key>
ETHERSCAN_API_KEY=<your-etherscan-v2-key>      # works across all chains

# Wallet — one key for every step. The Makefile auto-loads .env, so
# `make deploy-factory-base-sepolia` etc. pick this up without any further
# arguments. For live-contract deploys PRIVATE_KEY MUST be the key of
# DEPLOY_OPERATOR (sender-guarded salts revert for any other sender).
PRIVATE_KEY=0x...

# ⚠️ The operator EVERY live canonical address derives from
# (WalletFactory, ShrincsWallet, ShrincsPaymaster). This key must sign
# each canonical deploy on each chain, forever — losing it means losing
# the ability to materialize the canonical addresses on new chains.
DEPLOY_OPERATOR=0x...

# Deploy-time owners / params
FACTORY_OWNER=0x...                            # controls vetImplementation
MAX_FEE=1000000000000000                       # wallet creation fee (wei)
SHRINCS_PAYMASTER_OWNER=0x...                  # 02_DeployShrincs
SHRINCS_VERIFIER_PUBLIC_KEY=0x...              # 02_DeployShrincs — abi-encoded
                                               # SHRINCS.PublicKey bundle from
                                               # gen-shrincs-paymaster-verifier.mjs;
                                               # initialize derives the commitment
                                               # + leaf budget from it on-chain

# Sunset WOTS+ family only
DEPLOYER_ADDRESS=0xA1A3990Ea898123e4B107D0A2f614232bE428Ef1
PAYMASTER_OWNER=0x...                          # QuipPaymaster (WOTS+ era)

# Per-release (deploy-impl-* / vet-impl-* ONLY — the live deploy scripts
# derive the canonical factory address and accept no override)
FACTORY_ADDRESS=0x...
IMPLEMENTATION=0x...                           # filled in after deploy-impl
```

---

## v0.1.x — historical (CREATE2 via custom DeployDeployer at nonce=1)

`@quip.network/ethereum-sdk@0.1.7` and earlier (now vendored at `src/deprecated/v0`, npm subpath `./deprecated/v0`).
Deployer was bootstrapped via plain CREATE at nonce 1 from a fresh EOA;
downstream contracts used `keccak256("QUIP")` as the salt with no
per-contract versioning.

| Contract | Address |
|---|---|
| Deployer (v0) | `0xF768b4E4A314C9119587b8Cd35a89bDC228290b5` |
| WOTSPlus (v0) | `0x1Ad02caBfc65ed65FDF6da64108f04f71E2e8991` |
| QuipFactory (v0) | `0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99` |

Salt: `keccak256("QUIP")` = `0xd9fb07cc22ea59a9164c9fbaf3b898b3e6c5190454c06259cf5c99c889dc63f4`.
Live on Ethereum, Base, Optimism, Degen as of `0.1.7`.

The corresponding committed release bytecode lives under
`deployments/bytecode-v0-historical/` (archived; not consumed by any v1
script).
