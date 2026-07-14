# Deployments

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

> ⚠️ **Factory V2 (UUPS) supersedes the address above.** The QuipFactory
> became UUPS-upgradeable (impl + ERC-1967 proxy, like the paymaster) on
> fresh `V2` salts — the V1.1 salt is retired because CREATE3 ignores
> initcode, so reusing it would resolve to the old non-upgradeable factory
> on chains where it exists. The V2 proxy address (the permanent factory
> identity — wallets bake it in, CREATE3 wallet addressing derives from
> it) materializes on the next deploy; run `make predict-addresses` for
> the canonical value. The `0xd175…` V1.1 factory above remains on Base
> Sepolia as a retired artifact.

### Salts

| Contract | Salt preimage |
|---|---|
| Deployer (via CreateX, unchanged) | `QUIP:Deployer:V1` |
| WOTSPlus | `QUIP:WOTSPlus:V1.1` |
| QuipFactory impl (UUPS) | `QUIP:QuipFactory:Impl:V2` |
| QuipFactory proxy (canonical) | `QUIP:QuipFactory:Proxy:V2` |
| QuipFactory (retired, non-upgradeable) | `QUIP:QuipFactory:V1.1` |
| QuipWallet impl | `QUIP:QuipWallet:V1.1` |
| QuipPaymaster impl | `QUIP:QuipPaymaster:Impl:V1.1` |
| QuipPaymaster proxy | `QUIP:QuipPaymaster:Proxy:V1.1` |

### Deployer bootstrap

The Deployer is the only contract not deployed via solady CREATE3 — it
*hosts* solady CREATE3, so it can't deploy itself. Instead it's deployed
via **CreateX** at `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`, which is
itself pre-deployed on every chain via Nick's-method presigned tx.

CreateX salt mode: the raw salt `keccak256("QUIP:Deployer:V1")` has its
first 20 bytes as random hash output (neither `msg.sender` nor
`address(0)`), so CreateX's guard hits the "other" branch:
`guardedSalt = keccak256(abi.encode(salt))`. This means:
- **Unguarded**: any funded wallet can broadcast `DeployDeployer.s.sol`.
  No fresh-EOA / nonce-1 ritual.
- **Cross-chain identical**: the guarded salt is deterministic from the
  preimage, so CreateX deploys the Deployer at the same address on every
  chain that has CreateX.

Once the Deployer exists on a chain, every other Quip contract uses it
to deploy via solady CREATE3.

### Library linking

`QuipWallet` (the sunset WOTS+ implementation, `contracts/deprecated/wots/`)
calls into the `WOTSPlus` library at runtime — its compiled
bytecode contains a placeholder that must be replaced with WOTSPlus's
address before deploy. (`QuipFactory` no longer links WOTSPlus: the
WOTS+ decoupling removed its last dependency, so factory bytecode is
link-free.) Foundry handles the wallet linking via the
`[profile.deploy]` profile in `foundry.toml`:

```toml
[profile.deploy]
libraries = [
    "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol:WOTSPlus:0x7837b85Fa4D31a5af8FD28e66b18f156F66C3723"
]
```

Every script that touches `QuipWallet` bytecode runs under
`FOUNDRY_PROFILE=deploy`. The Makefile per-chain targets set this
automatically (harmless for the factory-only script).

### Deployment workflow

```
1. Predict addresses     make predict-addresses
                         # No env / RPC needed. Prints all canonical addresses.

2. Bootstrap Deployer    make deploy-deployer-<chain>
                         # CreateX-based; any funded wallet works.
                         # Skip if Deployer already at canonical address.

3. Deploy infra          make deploy-all-<chain>
                         # WOTSPlus + QuipFactory + QuipPaymaster (impl + proxy).
                         # Requires FACTORY_OWNER, MAX_FEE, PAYMASTER_OWNER in .env.

4. Deploy wallet impl    make deploy-impl-<chain>
                         # WOTS+ (sunset family) flow, script under script/deprecated/.
                         # Runs under FOUNDRY_PROFILE=deploy.

5. Vet wallet impl       IMPLEMENTATION=0x... make vet-impl-<chain>
                         # Factory owner whitelists the new impl.
```

`<chain>` is currently `base-sepolia`; see Makefile for the full list of
per-chain targets.

### Required environment variables

Put these in a project-local `.env` (Makefile auto-loads it). All
addresses below are examples — substitute your actual operator wallets.

```bash
# Chain RPC + Etherscan
API_URL_BASE_SEPOLIA=https://base-sepolia.g.alchemy.com/v2/<key>
ETHERSCAN_API_KEY=<your-etherscan-v2-key>      # works across all chains

# Wallet — one key for every step. The Makefile auto-loads .env, so
# `make deploy-all-base-sepolia` etc. pick this up without any further
# arguments. Forge derives the EOA address internally; no separate
# "deployer EOA" var is required.
PRIVATE_KEY=0x...

# Deploy-time owners / params
DEPLOYER_ADDRESS=0xA1A3990Ea898123e4B107D0A2f614232bE428Ef1
FACTORY_OWNER=0x...                            # controls vetImplementation
MAX_FEE=1000000000000000                       # wallet creation fee (wei)
PAYMASTER_OWNER=0x...                          # controls paymaster

# Per-release (only for deploy-impl-* / vet-impl-*)
FACTORY_ADDRESS=0xd175378EC511e56BbffcC802375C6ad7d892c083
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
