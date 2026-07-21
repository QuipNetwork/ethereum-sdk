# Quip Network SDK

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](#license)

This repository contains the smart contracts and TypeScript SDK for the Quip Network — post-quantum-secured smart-contract wallets on EVM chains.

**Active development — not production-ready.** APIs, contract addresses, and the on-chain key schema may change between releases. See [TODO.md](TODO.md) for outstanding work.

Active Dev Branch : deploy/testnet

---

## Directory Map 

| Path                   | Purpose                                                                                                     |
| ---------------------- | ----------------------------------------------------------------------------------------------------------- |
| `contracts/`           | Live Solidity contracts: `WalletFactory` (UUPS), the SHRINCS wallet family (`shrincs/`); sunset code (incl. the `Deployer`) under `deprecated/`. |
| `contracts/deprecated/` | Sunset WOTS+ wallet family (`wots/`) + `QuipPaymaster`. Fully functional, still tested; no new features.   |
| `script/`              | Foundry deployment scripts (`*.s.sol`); sunset-family scripts under `script/deprecated/`.                   |
| `scripts/`             | TypeScript operational scripts: `release.ts`, `fundDeployer.cts`, `drainDeployer.cts`, `balance.cts`, etc.  |
| `src/v1/`              | Current TypeScript SDK: shared surface (`src/v1/index.ts`) + SHRINCS clients (`src/v1/shrincs/`).           |
| `src/deprecated/`      | Sunset SDKs: the WOTS+ half of v1 (`v1/`) and the legacy v0 SDK (`v0/`).                                    |
| `test/`                | Foundry tests (Solidity); sunset-family suites under `test/deprecated/`.                                    |
| `src/v1/tests/`        | Jest tests (TypeScript). SHRINCS: `src/v1/shrincs/tests/`; WOTS+: `src/deprecated/v1/tests/`.               |
| `deploy/midl_regtest/` | Hardhat deploy scripts for MIDL Bitcoin L2 only.                                                            |
| `Makefile`             | The canonical interface for build / test / deploy.             |

## Documentation map

| Document                                                   | Context                                                                                                                 |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **This README**                                            | Setup, build/test commands, deploy commands.                                                                            |
| **[SDK_README.md](SDK_README.md)**                         | You're consuming the published `@quip.network/ethereum-sdk` npm package.                                                |
| **[INVARIANTS.md](INVARIANTS.md)**                         | You're auditing, extending, or porting the contracts/SDK. All cryptographic, on-chain, and SDK invariants in one place. |
| **[GOVERNANCE.md](GOVERNANCE.md)**                         | Factory + paymaster trust model: what the owner can do, what they can't, recommended posture, and the planned move to on-chain governance. |
| **[DEPLOYMENTS.md](DEPLOYMENTS.md)**                       | Canonical contract addresses, per-chain deployment status, salt schemes.                                                |
| **[MIDL-DEPLOYMENT.md](MIDL-DEPLOYMENT.md)**               | Deploying onto MIDL (chain 777). Separate from the EVM workflow.                                                        |
| **[MIDL-REOWN-INTEGRATION.md](MIDL-REOWN-INTEGRATION.md)** | Integrating Quip with Reown AppKit on MIDL.                                                                             |
| **[TODO.md](TODO.md)**                                     | Roadmap and known gaps.                                                                                                 |

---

## Prerequisites

- **Node.js** ≥ 20 and a package manager (`npm`, `bun`, `yarn`, or `pnpm`). Examples below show `bun` but `npm run <script>` works identically.
- **[Foundry](https://book.getfoundry.sh/getting-started/installation)** — `forge`, `cast`, `anvil`. The canonical toolchain for compiling, testing, and deploying the contracts on EVM chains.
- **[soldeer](https://soldeer.xyz)** — Foundry's package manager. Run `forge soldeer install` (or `make install`) once after cloning.
- **GNU Make** — drives every workflow via the [`Makefile`](Makefile).
- **[jq](https://jqlang.org)** — required by the storage-layout snapshot/check targets.

Hardhat is also installed, but it's used **only** for MIDL deploy scripts (`deploy/midl_regtest/`). All EVM compilation, testing, deployment, and release-bytecode generation go through Foundry. See `hardhat.config.cts` for the scope of the Hardhat configuration. 

## Installation

> ⚠️ `npm install` alone is **not** sufficient for a fresh clone — the SDK build (`forge build` → `copy-abi` → `tsc`) needs Foundry's `soldeer` dependencies materialized first. Use `make install` below; it runs `forge soldeer install` and `npm install` together.

```bash
git clone <repo>
cd ethereum-sdk
make install          # forge soldeer install + npm install
```

## Environment setup

Copy `.env.example` to `.env`. 

Variables are loaded automatically by the `Makefile` and Foundry's `[rpc_endpoints]` table. The base set below is enough for building, testing, running utility scripts, and SDK development:

```shell
# RPC endpoints (one per chain you target)
API_URL_SEPOLIA=https://eth-sepolia.g.alchemy.com/v2/...
API_URL_BASE_SEPOLIA=https://base-sepolia.g.alchemy.com/v2/...
API_URL_OP_SEPOLIA=https://opt-sepolia.g.alchemy.com/v2/...
API_URL_MAINNET=https://eth-mainnet.g.alchemy.com/v2/...
API_URL_BASE=https://base-mainnet.g.alchemy.com/v2/...
API_URL_OPTIMISM=https://opt-mainnet.g.alchemy.com/v2/...

# Operator wallet — signs any broadcast (deploys, vetting, utility scripts).
# For test/build only, can be omitted. For live-contract deploys this MUST
# be the key of DEPLOY_OPERATOR (see the Deployment section).
PRIVATE_KEY=0x...

# Etherscan v2 — one key covers Ethereum, Base, Optimism, and their L2 testnets.
# Required when deploys pass --verify (the default).
ETHERSCAN_API_KEY=...
```

Deployment targets require additional variables — they're listed in the [Deployment](#deployment) section alongside the targets that consume them, so you only set what you actually need.

Network aliases must match `[rpc_endpoints]` in `foundry.toml`:

| Alias | Chain | Chain ID |
|---|---|---|
| `sepolia` | Ethereum Sepolia | 11155111 |
| `base_sepolia` | Base Sepolia | 84532 |
| `op_sepolia` | Optimism Sepolia | 11155420 |
| `mainnet` | Ethereum Mainnet | 1 |
| `base` | Base Mainnet | 8453 |
| `optimism` | Optimism Mainnet | 10 |

MIDL Testnet (chain 777) uses a different toolchain — see [MIDL-DEPLOYMENT.md](MIDL-DEPLOYMENT.md).

---

## Contract development (Foundry)

```bash
make build                 # forge build
make test                  # forge test
make test-v                # forge test -vvv (verbose stack traces)
make gas                   # forge test --gas-report
make snapshot              # forge snapshot
make lint                  # solhint contracts/**/*.sol
make format                # prettier across .ts/.js/.json/.sol
```

`forge build` and `forge test` use the **default** profile, which compiles WOTSPlus as an inline library so tests don't need a pre-deployed address. The **`deploy`** profile (`FOUNDRY_PROFILE=deploy`) links WOTSPlus at the CREATE3-predicted address from `foundry.toml` and is used only by deployment scripts.

### Local node

```bash
anvil                      # local EVM node on :8545
```

### Storage layout drift gate

The WOTS+ wallet uses ERC-7201 namespaced storage (`quip.storage.wallet.wotsplus`), which `forge inspect storageLayout` cannot see directly. A test-only probe contract surfaces the layout, and the canonical fixture is `test/deprecated/fixtures/WOTSPlusImplementation.storageLayout.json`:

```bash
make storage-layout-check       # CI gate — fails if layout drifted
make storage-layout-snapshot    # regenerate fixture (only after intentional change)
```

If `storage-layout-check` fails, the upgrade path is broken unless you also write a corresponding migrator. Do not regenerate the snapshot to silence the gate.

---

## SDK development (TypeScript)

The SDK is the npm package `@quip.network/ethereum-sdk`. It depends on the compiled contract ABIs, so SDK builds always include a contract build.

```bash
bun run build              # forge build + copy ABIs + tsc
bun run test:unit          # jest (TypeScript unit + integration tests)
bun run smoke:fork         # jest, but only the fork smoke test
bun run smoke:tarball      # pack + dry-install the SDK to verify exports
```

`bun run` is interchangeable with `npm run` here — both invoke the same `package.json` scripts. Use whichever you prefer.

### Publishing a release

The release script regenerates `src/v1/addresses.json` and `deployments/bytecode/` from the current Foundry build (compiler settings in `foundry.toml`), then prepares the tarball for `npm publish`:

```bash
make release               # forge build + tsx scripts/release.ts
bun run smoke:tarball      # verify the tarball before publishing
npm publish
```

`scripts/release.ts` reads Foundry artifacts from `out/`, computes CREATE3 addresses (`DEPLOY_OPERATOR` is REQUIRED — live canonical addresses are sender-guarded CreateX deployments and therefore a function of the operator; sunset WOTS+-era rows keep their Deployer derivation), links the WOTSPlus library into the `QuipWallet` (WOTS+ implementation) bytecode — the factory links no libraries since the WOTS+ decoupling — and snapshots each release under `deployments/bytecode/<Contract>.sol/` with the compiler settings recorded verbatim from each artifact's metadata. MIDL deploys consume those snapshots via `lib/deploy.cts::loadReleaseBytecode` so the bytecode actually deployed on MIDL matches what was compiled by Foundry for the EVM chains.

---

## Deployment

EVM deployments go through Foundry scripts in `script/`, driven by the Makefile. The live flow is two NUMBERED scripts run in order — `01_DeployFactory.s.sol`, then `02_DeployShrincs.s.sol` — both idempotent. Each step writes a broadcast log to `broadcast/<Script>.s.sol/<chainId>/` for replay/inspection.

> ⚠️ **Steps 1 and 2 are governance-sensitive.** `deploy-factory-<chain>` sets the initial WalletFactory owner; `deploy-shrincs-<chain>` sets the ShrincsPaymaster owner and requires the caller to be the factory owner (vetting is `onlyOwner`), as does `vet-impl-<chain>`.
> Double-check `FACTORY_OWNER` / `SHRINCS_PAYMASTER_OWNER` are addresses you actually want as the long-term operators. Both steps require `PRIVATE_KEY` to be **`DEPLOY_OPERATOR`'s key** — live canonical addresses are sender-guarded CreateX deployments, a function of the operator address, and no other key can consume the canonical salts.

### Pipeline (per chain)

The numbered steps below also list the `.env` variables each one consumes. Set only the ones for the steps you're running.

**0. Predict the CREATE3 addresses for the current bytecode.**

```bash
DEPLOY_OPERATOR=0x... make predict-addresses
# or: DEPLOY_OPERATOR=0x... forge script script/PredictAddresses.s.sol
```

No RPC needed. `DEPLOY_OPERATOR` is required for the live-contract rows (their addresses are a function of it — sender-guarded CreateX salts); without it only the sunset WOTS+-era rows print.

**1. Deploy the WalletFactory (UUPS impl + ERC-1967 proxy).** ⚠️ **Governance-sensitive. Contact Rick first.** `FACTORY_OWNER` becomes the only address that can vet implementations, collect creation fees, and **upgrade the factory implementation** on this chain going forward. The factory PROXY address is the permanent identity every wallet bakes in — the impl behind it is replaceable via `upgradeToAndCall`.

```bash
make deploy-factory-base-sepolia
```

Env: `PRIVATE_KEY` (must be `DEPLOY_OPERATOR`'s key), `DEPLOY_OPERATOR` (the operator every live canonical address derives from — guard that key), `FACTORY_OWNER`, `MAX_FEE` (WalletFactory creation fee in wei), `ETHERSCAN_API_KEY`.

**2. Deploy the Shrincs family — ShrincsWallet impl (vetted; becomes `latestWalletImpl`) + ShrincsPaymaster (impl + proxy).** The script locates the factory at its canonical derived address only — there is no `FACTORY_ADDRESS` override — and refuses to broadcast unless that address hosts an ERC-1967 proxy owned by the operator. ⚠️ `SHRINCS_PAYMASTER_OWNER` becomes the only address that can configure the ShrincsPaymaster; `PRIVATE_KEY` must also be the factory owner (vetting).

```bash
make deploy-shrincs-base-sepolia
```

Env: `PRIVATE_KEY`, `DEPLOY_OPERATOR`, `SHRINCS_PAYMASTER_OWNER`, `SHRINCS_VERIFIER_COMMITMENT`, `SHRINCS_VERIFIER_MAX_SIGNATURES`, `ETHERSCAN_API_KEY`.

**Ops: vet an implementation on the factory.** ⚠️ **Requires the calling `PRIVATE_KEY` to be the factory's current owner.** The factory's `vetImplementation` is `onlyOwner`, so any other key produces a revert; a successful vet makes the impl the new `latestWalletImpl`. **Contact Rick** for coordination if you're not the registered factory owner on the target chain.

```bash
IMPLEMENTATION=0x... make vet-impl-base-sepolia
```

Env: `PRIVATE_KEY` (must equal the factory owner), `FACTORY_ADDRESS`, `IMPLEMENTATION`.

**Sunset WOTS+ family (optional, frozen under `script/deprecated/`).** `make deploy-deployer-<chain>` bootstraps the legacy `Deployer` (anyone can run it — unguarded salt), then `make deploy-impl-<chain>` deploys a WOTSPlusImplementation through it under `FOUNDRY_PROFILE=deploy` (env: `PRIVATE_KEY`, `DEPLOYER_ADDRESS`, `FACTORY_ADDRESS`). Vetting a WOTS+ impl AFTER step 2 would flip `latestWalletImpl` back to WOTS+ — the intended default is Shrincs.

### Adding a new chain

Per-chain Makefile targets currently exist for **base_sepolia** as a worked example. To add support for another chain:

1. Add an alias in `foundry.toml` `[rpc_endpoints]` and `[etherscan]`.
2. Copy the `*-base-sepolia` targets in the `Makefile` and rename them for the new alias.
3. Run steps 0–2 above against the new alias.

For one-off runs against arbitrary chains, use the bare `make deploy-*` targets with an explicit RPC override:

```bash
RPC_URL=$API_URL_SEPOLIA make deploy-factory
RPC_URL=$API_URL_SEPOLIA make deploy-shrincs
```

Canonical contract addresses and salts are in [DEPLOYMENTS.md](DEPLOYMENTS.md).

### Utility scripts

```bash
make fund-deployer         # send ETH from PRIVATE_KEY to the operator deployer
make drain-deployer        # sweep remaining ETH back out
make balance               # print operator balances across configured chains
```

All three are TypeScript scripts in `scripts/` invoked via `npx tsx`. They read RPC and key material from `.env`. The `drain-deployer` script replaces the old `npx hardhat run scripts/drainDeployer.ts --network <name>` invocation that was used in the V1 deployment flow.

### Contract verification

Deploy targets pass `--verify` to forge by default. Etherscan v2 is configured per-chain in `foundry.toml [etherscan]`, so a single `ETHERSCAN_API_KEY` covers mainnet, Base, Optimism, and their L2 testnets.

To verify an already-deployed contract independently:

```bash
# WOTSPlus library (no constructor args)
forge verify-contract \
  --rpc-url base_sepolia \
  --chain base_sepolia \
  0x742376ec2A8237Ba46E1ACDDfF315f1Ef25E4C0e \
  @quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol:WOTSPlus

# WalletFactory (constructor: address initialOwner, uint256 maxFee)
forge verify-contract \
  --rpc-url base_sepolia \
  --chain base_sepolia \
  --constructor-args $(cast abi-encode "constructor(address,uint256)" "$FACTORY_OWNER" "$MAX_FEE") \
  0xE567d318819c067c26fC1E44D04beD2b4FE93BCC \
  contracts/WalletFactory.sol:WalletFactory
```

The above addresses are the deterministic CREATE3 addresses currently registered in `src/v1/addresses.json` (the SDK's "default" entry, shared across the chains in `SHARED_DEPLOYMENT_CHAIN_IDS`). Pre-V2 CREATE2 mainnet addresses are listed separately in [DEPLOYMENTS.md](DEPLOYMENTS.md).

---

## License

Copyright (C) 2024–2026 quip.network

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. See [COPYING](COPYING) for the full license text.
