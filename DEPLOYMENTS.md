# Deployments

## v1 — canonical addresses (CREATE3 via CreateX-bootstrapped Deployer)

All v1 contracts share the same addresses on every chain where CreateX is
available. Computed before any deploy is broadcast — run `make
predict-addresses` to see them locally with no env vars and no RPC.

| Contract | Address |
|---|---|
| Deployer | `0xA1A3990Ea898123e4B107D0A2f614232bE428Ef1` |
| WOTSPlus | `0x742376ec2A8237Ba46E1ACDDfF315f1Ef25E4C0e` |
| QuipFactory | `0xE567d318819c067c26fC1E44D04beD2b4FE93BCC` |
| QuipWallet (impl) | `0x81648CBFA79aD8f2c4A59E0DdeA03b1BC8b34cfb` |
| QuipPaymaster (impl) | `0xeEFb077B9A0B63BA06ce72Ae07E016A9efA82ed7` |
| QuipPaymaster (proxy, canonical) | `0x4A952d592fAe490762f492dC65487eE2B53Ef554` |

> The QuipPaymaster proxy is the user-facing paymaster address; the impl
> behind it is intentionally inert (`_disableInitializers()` runs in its
> constructor).

### Salts

| Contract | Salt preimage |
|---|---|
| Deployer (via CreateX) | `QUIP:Deployer:V1` |
| WOTSPlus | `QUIP:WOTSPlus:V1` |
| QuipFactory | `QUIP:QuipFactory:V1` |
| QuipWallet impl | `QUIP:QuipWallet:V1` |
| QuipPaymaster impl | `QUIP:QuipPaymaster:Impl:V1` |
| QuipPaymaster proxy | `QUIP:QuipPaymaster:Proxy:V1` |

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

`QuipWallet` and `QuipFactory` both call into the `WOTSPlus` library at
runtime — their compiled bytecode contains a placeholder that must be
replaced with WOTSPlus's address before deploy. Foundry handles this via
the `[profile.deploy]` profile in `foundry.toml`:

```toml
[profile.deploy]
libraries = [
    "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol:WOTSPlus:0x742376ec2A8237Ba46E1ACDDfF315f1Ef25E4C0e"
]
```

Every script that touches `QuipWallet` or `QuipFactory` bytecode runs
under `FOUNDRY_PROFILE=deploy`. The Makefile per-chain targets set this
automatically.

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
                         # Per-release flow, runs under FOUNDRY_PROFILE=deploy.

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
FACTORY_ADDRESS=0xE567d318819c067c26fC1E44D04beD2b4FE93BCC
IMPLEMENTATION=0x...                           # filled in after deploy-impl
```

---

## v0.1.x — historical (CREATE2 via custom DeployDeployer at nonce=1)

`@quip.network/ethereum-sdk@0.1.7` and earlier (now vendored at `/v0`).
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
