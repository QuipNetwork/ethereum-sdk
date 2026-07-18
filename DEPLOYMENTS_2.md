# Deployment Guide

Step-by-step runbook for deploying the Quip contract suite to an EVM chain, written
for someone doing it for the first time. The canonical address/salt registry and
deployment history live in [`DEPLOYMENTS.md`](DEPLOYMENTS.md) — this document is the *how*.

## Deployment model

Everything is deterministic, in two layers:

1. **CreateX bootstraps the Deployer.** [CreateX](https://github.com/pcaversaccio/createx)
   is a public deploy factory pre-installed at
   `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed` on virtually every EVM chain
   (Nick's-method presigned tx). [`script/DeployDeployer.s.sol`](script/DeployDeployer.s.sol)
   asks it to CREATE3-deploy our `Deployer` with salt `keccak256("QUIP:Deployer:V1")`.
   Any funded wallet can broadcast this — no nonce ritual, no special EOA.
2. **The Deployer deploys everything else.** Every other contract goes through
   `Deployer` (solady CREATE3). A CREATE3 address depends **only on
   (Deployer address, salt)** — not on the broadcasting wallet, not on constructor
   args, not on the chain.

Same Deployer + same salts on every chain ⇒ **same addresses on every chain**.

```sh
make predict-addresses   # prints every canonical address — no env vars, no RPC
```

### What gets deployed

| Contract | Role | Family |
| --- | --- | --- |
| `Deployer` | CREATE3 factory for everything below | infra |
| `WOTSPlus` (library) | hash-sig library the sunset wallet links against | shared |
| `WalletFactory` (impl + ERC-1967 proxy) | deploys wallet proxies; owner vets wallet implementations | shared |
| `ShrincsWallet` (impl) | go-forward post-quantum wallet implementation | SHRINCS |
| `ShrincsPaymaster` (impl + proxy) | go-forward paymaster | SHRINCS |
| `WOTSPlusImplementation` (impl) | sunset wallet implementation | WOTS+ (sunset) |
| `QuipPaymaster` (impl + proxy) | sunset paymaster | WOTS+ (sunset) |

The **proxy** addresses are the permanent user-facing identities (they survive
implementation upgrades); the impls behind them are inert
(`_disableInitializers()`).

> ⚠️ The SHRINCS impls hard-pin the external `SHRINCS256sKeccak` ERC-7913 verifier at
> `0xb76f5acfa4f1e993b36C9c72eD7514eC2c80F00A`. That contract is deployed by
> [hashsigs-solidity](https://gitlab.com/quip.network/hashsigs-solidity), **not this
> repo** — on a fresh chain it must exist before any SHRINCS deploy (the scripts
> fail closed if it doesn't).

### Salt convention

Preimages follow `QUIP:<Contract>[:Impl|:Proxy]:V<version>` — full table in
[`DEPLOYMENTS.md`](DEPLOYMENTS.md#salts). Two twists:

- The Deployer's salt is wrapped by CreateX into `keccak256(abi.encode(salt))`
  ("guarded" mode) — deterministic, so still cross-chain identical.
- The Shrincs **impl** salts append `SHRINCSParams.PROFILE_ID` (the verifier
  scheme tag), so an impl built for a different cryptographic scheme structurally
  lands at a different address.

**Version-bump rule:** CREATE3 ignores initcode — reusing a salt on a chain where
it was already deployed silently keeps the *old* code. New contract code ⇒ new
salt version (bump it in the deploy script *and* `script/PredictAddresses.s.sol`).

## Per-chain deploy order

1. **CreateX** — pre-deployed on virtually all chains; the bootstrap script reverts if missing.
2. **Deployer** — `make deploy-deployer-<chain>`.
3. **SHRINCS256sKeccak verifier** — deployed from hashsigs-solidity if not already live (sibling verifier first; commands in that repo's `DEPLOYMENTS.md`).
4. **Everything else** — `make deploy-all-<chain>` (shared infra + both families, vetted).
5. **Later impl releases only** — `make deploy-impl-<chain>` + `make vet-impl-<chain>`.

## Prerequisites

- [Foundry](https://getfoundry.sh) (`forge`, `cast`), Node 18+, `make`, then `make install`
  (soldeer + npm deps).
- A funded EOA on the target chain (`PRIVATE_KEY`). It only pays gas — it does not
  affect any address. **For `deploy-all` it must also be the `FACTORY_OWNER`**,
  because vetting wallet impls is owner-gated.
- CreateX live on the target chain — probe with:

  ```sh
  cast code 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed --rpc-url $API_URL_BASE_SEPOLIA
  # non-empty hex = present; "0x" = missing (chain not supported until it is)
  ```

- SHRINCS verifier live (same probe against `0xb76f5acfa4f1e993b36C9c72eD7514eC2c80F00A`).
- `ETHERSCAN_API_KEY` (v2, multichain) — the per-chain targets pass `--verify`.

## Environment

```sh
cp .env.example .env   # .env is gitignored — never commit keys
```

`.env.example` lists every variable below. `PRIVATE_KEY` must be `0x`-prefixed
(forge scripts read it with `vm.envUint`). The Makefile auto-loads `.env` and
exports it to child processes, so `make …` needs no `source`. Values must be
**unquoted**. Raw `forge`/`cast` commands don't get this — run `source .env`
first for those.

| Variable | Required for | What it is |
| --- | --- | --- |
| `PRIVATE_KEY` | every broadcast | `0x`-prefixed key of the operations EOA. Pays gas; must be the factory owner for any step that vets (`deploy-all`, `vet-impl`). |
| `DEPLOYER_ADDRESS` | `deploy-all`, impl/vet steps | Deployer **contract** (not the EOA). Canonical: `0xA1A3990Ea898123e4B107D0A2f614232bE428Ef1`. Public, not a secret. |
| `FACTORY_OWNER` | `deploy-all` | Initial `WalletFactory` owner — controls vetting, fees, UUPS upgrades. |
| `MAX_FEE` | `deploy-all` | Max wallet-creation fee in wei (e.g. `1000000000000000` = 0.001 ETH). Non-zero. |
| `PAYMASTER_OWNER` | `deploy-all` | Initial `QuipPaymaster` proxy owner (sunset family). |
| `SHRINCS_PAYMASTER_OWNER` | `deploy-all`, shrincs-only | Initial `ShrincsPaymaster` proxy owner. |
| `SHRINCS_VERIFIER_COMMITMENT` | `deploy-all`, shrincs-only | `bytes32` verifier key-bundle commitment. Non-zero (initialize reverts otherwise). |
| `SHRINCS_VERIFIER_MAX_SIGNATURES` | `deploy-all`, shrincs-only | Verifier stateful signature budget (`uint32`, non-zero). |
| `SHRINCS_VERIFIER_HASH_SUITE` | optional | Defaults to the keccak-256 suite — the only one the on-chain library verifies; leave unset. (The `DeployAll` header mentions `SHRINCS_VERIFIER_PARAM_SET_ID`; the code actually reads this variable.) |
| `API_URL_<CHAIN>` | per chain | RPC URL, e.g. `API_URL_BASE_SEPOLIA`. Wired to the `[rpc_endpoints]` aliases in `foundry.toml`. |
| `ETHERSCAN_API_KEY` | `--verify` | Etherscan v2 multichain key. |
| `FACTORY_ADDRESS` | impl/vet steps, shrincs-only | Existing `WalletFactory` **proxy** address. |
| `IMPLEMENTATION` | `vet-impl` | Freshly deployed wallet impl address to vet. |

## Deploying

`<chain>` is `base-sepolia` or `op-sepolia` — the only chains with per-chain
targets today (the `foundry.toml` aliases also cover `sepolia`, `mainnet`, `base`,
`optimism`; see [Adding a new chain](#adding-a-new-chain)).

> ⚠️ **Use the per-chain targets, not the bare ones.** The un-suffixed targets
> (`make deploy-all`, `make deploy-deployer`, …) interpolate `$(RPC_URL)`, which
> nothing in `.env.example` defines — they only work if you export `RPC_URL`
> yourself. The per-chain targets use the `foundry.toml` aliases and just work.

### 0. Predict

```sh
make predict-addresses
```

Compare against the registry in `DEPLOYMENTS.md`. Any mismatch means a salt or
dependency drifted — stop and investigate before broadcasting.

### 1. Dry-run

There is no `deploy-dry` make target (yet) — simulate with raw forge by omitting
`--broadcast`:

```sh
source .env
FOUNDRY_PROFILE=deploy forge script script/DeployAll.s.sol --rpc-url base_sepolia
```

Forge simulates the whole run against the live chain and prints what would
deploy, without sending anything.

### 2. Bootstrap the Deployer

```sh
make deploy-deployer-base-sepolia
```

Idempotent — if the Deployer already sits at the canonical address it logs
"already deployed" and exits. Any funded wallet works for this step.

### 3. Deploy + vet everything

```sh
make deploy-all-base-sepolia
```

What this does (script: [`script/DeployAll.s.sol`](script/DeployAll.s.sol)):

1. Shared infra — `WOTSPlus` library, `WalletFactory` impl + proxy.
2. SHRINCS family — `ShrincsWallet` impl (vetted **first**), `ShrincsPaymaster` impl + proxy.
3. WOTS+ family — `WOTSPlusImplementation` (vetted **last**), `QuipPaymaster` impl + proxy.

The vetting order is deliberate: the factory's `latestWalletImpl` is whatever was
vetted last, and the WOTS+ SDK's `createWallet` uses it, so WOTS+ stays the
default. The script asserts this at the end.

Notes:

- The target sets `FOUNDRY_PROFILE=deploy` for you (links the `WOTSPlus` library
  into the wallet impl — see `[profile.deploy]` in `foundry.toml`).
- `--verify` is included; source verification needs `ETHERSCAN_API_KEY`.
- Idempotent: re-runs skip anything already deployed or already vetted.
- `PRIVATE_KEY` must be the factory owner (steps 2–3 vet).

### Shrincs-only deploy (no make target)

[`script/DeployAllShrincs.s.sol`](script/DeployAllShrincs.s.sol) deploys just the
SHRINCS family against an existing factory, but has **no Makefile target** — raw
forge only:

```sh
source .env
forge script script/DeployAllShrincs.s.sol --rpc-url base_sepolia \
    --private-key $PRIVATE_KEY --broadcast --verify
```

Needs `FACTORY_ADDRESS` in addition to the SHRINCS vars.

> ⚠️ **Side effect:** vetting the ShrincsWallet flips `latestWalletImpl` to
> Shrincs, so the WOTS+ SDK's `createWallet` would start resolving to the wrong
> family. `DeployAll` re-vets WOTS+ last precisely to avoid this. Run the
> standalone script only when making Shrincs the default is intended.

## Post-deploy checks

Addresses come from `make predict-addresses`; receipts land under
`broadcast/<Script>.s.sol/<chainid>/`.

```sh
source .env
cast call <WalletFactory proxy> "owner()(address)"           --rpc-url $API_URL_BASE_SEPOLIA
cast call <WalletFactory proxy> "latestWalletImpl()(address)" --rpc-url $API_URL_BASE_SEPOLIA
cast call <ShrincsPaymaster proxy> "owner()(address)"         --rpc-url $API_URL_BASE_SEPOLIA
```

Expect: factory owner = `FACTORY_OWNER`, `latestWalletImpl` =
`WOTSPlusImplementation` (after `DeployAll`), paymaster owner =
`SHRINCS_PAYMASTER_OWNER`.

Then record the deployment: update `src/v1/addresses.json` and the registry
tables in `DEPLOYMENTS.md`.

## Releasing a new wallet impl (sunset WOTS+ flow)

Only needed when shipping new `WOTSPlusImplementation` code. Bump the salt version
in `script/deprecated/DeployImplementation.s.sol` (and `PredictAddresses.s.sol`)
first — the old salt would silently resolve to the old code.

```sh
make deploy-impl-base-sepolia                       # needs FACTORY_ADDRESS
IMPLEMENTATION=0x... make vet-impl-base-sepolia     # factory owner whitelists it
```

Vetting sets `latestWalletImpl` to the new impl.

## Adding a new chain

1. Probe CreateX on the chain (see [Prerequisites](#prerequisites)). Missing ⇒ blocked.
2. Ensure `SHRINCS256sKeccak` (and its sibling verifier, which must go first) are
   deployed there via hashsigs-solidity.
3. Add `API_URL_<CHAIN>` to `.env`; add `[rpc_endpoints]` + `[etherscan]` entries
   in `foundry.toml` if not already present.
4. Copy the `*-base-sepolia` Makefile block into `*-<chain>` targets pointing at
   the new alias.
5. Dry-run, confirm predicted addresses match the canonical registry, then
   `make deploy-deployer-<chain>` and `make deploy-all-<chain>`.
6. Run the post-deploy checks; update `src/v1/addresses.json` and `DEPLOYMENTS.md`.

## MIDL

MIDL (Bitcoin execution layer) uses a completely different path — hardhat-deploy
scripts under `deploy/midl_regtest/` (`00_deploy_deployer` → `05_vet_wallet`),
invoked with `npx hardhat deploy --network midl_regtest --tags <tag>`. See the
header of [`MIDL-DEPLOYMENT.md`](MIDL-DEPLOYMENT.md); the rest of that file is
background research, not a runbook.

## Known gaps

Documented here so the guide doesn't silently paper over them:

- `DeployAllShrincs.s.sol` has no Makefile target (raw forge only, above).
- No `deploy-dry` targets — dry-run is raw forge without `--broadcast`.
- `.env.example` lacks all deploy variables and its "no `0x` prefix" note is
  wrong for the forge flow.
- Bare `deploy-*` targets depend on an undefined `RPC_URL`.
- `DeployAll`'s header comment mentions `SHRINCS_VERIFIER_PARAM_SET_ID`; the code
  reads `SHRINCS_VERIFIER_HASH_SUITE`.
