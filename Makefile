.PHONY: build test clean format lint lint-fix snapshot gas install update release \
       deploy-deployer deploy-wotsplus deploy-factory deploy-all \
       deploy-impl vet-impl predict-addresses \
       predict-base-sepolia deploy-deployer-base-sepolia deploy-all-base-sepolia \
       deploy-impl-base-sepolia vet-impl-base-sepolia \
       predict-op-sepolia deploy-deployer-op-sepolia deploy-all-op-sepolia \
       deploy-impl-op-sepolia vet-impl-op-sepolia \
       fund-deployer drain-deployer balance \
       storage-layout-snapshot storage-layout-check

# ── Auto-load .env ────────────────────────────────────────────────
# Loads KEY=VALUE pairs from .env into Make's variable space and exports
# them so child processes (forge, npx, …) see them. Values must be
# unquoted (Make doesn't do shell-style parsing) — e.g.
#   PRIVATE_KEY=0xab12…
#   API_URL_BASE_SEPOLIA=https://base-sepolia.g.alchemy.com/v2/…
# A missing .env is silently ignored — the unscoped `make build`,
# `make test`, etc. don't need any of these.
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# ── Build & Test ──────────────────────────────────────────────────

build:
	forge build

test:
	forge test

test-v:
	forge test -vvv

test-unit:
	node --experimental-vm-modules node_modules/jest/bin/jest.js --config jest.config.cjs

clean:
	forge clean
	rimraf dist out cache_forge

format:
	prettier --write "**/*.{ts,js,json,sol}"

lint:
	npx solhint 'contracts/**/*.sol'

lint-fix:
	npx solhint --fix 'contracts/**/*.sol'

snapshot:
	forge snapshot

gas:
	forge test --gas-report

# ── Storage Layout ────────────────────────────────────────────────
# Snapshot the WOTSPlusImplementation ERC-7201 namespace layout (`WOTSPlusStorage.Layout`)
# via the test-only probe contract `WOTSPlusImplementationLayoutProbe`. ERC-7201 namespaced
# storage is invisible to `forge inspect storageLayout` directly because it
# isn't a top-level state variable; the probe wraps the struct as a public
# state var so solc emits the full per-field slot/offset/type breakdown.
#
# The pipeline strips solc-internal IDs (`astId`, struct-name suffixes like
# `t_struct(Foo)1234_storage` → `t_struct(Foo)_storage`) so the fixture is
# stable across recompilations and only flips when actual layout changes.
#
# Usage:
#   make storage-layout-snapshot  # regenerate fixture (after intentional change)
#   make storage-layout-check     # CI gate; fails on drift
STORAGE_LAYOUT_FIXTURE := test/deprecated/fixtures/WOTSPlusImplementation.storageLayout.json
STORAGE_LAYOUT_NORMALIZE := walk(if type == "object" and has("astId") then del(.astId) else . end) \
	| walk(if type == "string" then gsub("t_struct\\((?<n>[^)]+)\\)\\d+_storage"; "t_struct(\(.n))_storage") else . end) \
	| .types |= with_entries(.key |= sub("t_struct\\((?<n>[^)]+)\\)\\d+_storage"; "t_struct(\(.n))_storage"))

storage-layout-snapshot:
	forge inspect WOTSPlusImplementationLayoutProbe storageLayout --json \
		| jq '$(STORAGE_LAYOUT_NORMALIZE)' > $(STORAGE_LAYOUT_FIXTURE)
	@echo "✅ Wrote $(STORAGE_LAYOUT_FIXTURE)"

storage-layout-check:
	@forge inspect WOTSPlusImplementationLayoutProbe storageLayout --json \
		| jq '$(STORAGE_LAYOUT_NORMALIZE)' \
		| diff -u $(STORAGE_LAYOUT_FIXTURE) - \
		|| (echo ""; echo "❌ Storage layout drift detected."; \
		    echo "   Run 'make storage-layout-snapshot' if the change is intentional."; \
		    exit 1)
	@echo "✅ Storage layout matches fixture."

# ── Dependencies ──────────────────────────────────────────────────

install:
	forge soldeer install
	npm install

update:
	forge soldeer update

# ── SDK ───────────────────────────────────────────────────────────

release:
	forge build && npx tsx scripts/release.ts

copy-abi:
	node scripts/copy-abi.js

sdk:
	forge build && npm run copy-abi && tsc -p tsconfig.build.json

# ── Deploy (requires PRIVATE_KEY, RPC_URL env vars) ──────────────

deploy-deployer:
	forge script script/deprecated/DeployDeployer.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

deploy-wotsplus:
	forge script script/deprecated/DeployWOTSPlus.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

deploy-factory:
	FOUNDRY_PROFILE=deploy forge script script/DeployWalletFactory.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

deploy-all:
	FOUNDRY_PROFILE=deploy forge script script/DeployAll.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --verify

deploy-impl:
	FOUNDRY_PROFILE=deploy forge script script/deprecated/DeployImplementation.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

vet-impl:
	forge script script/VetImplementation.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

predict-addresses:
	forge script script/PredictAddresses.s.sol

# ── Per-chain deploy convenience targets ──────────────────────────
# Each target maps to a [rpc_endpoints] alias in foundry.toml and reads
# its env vars from .env. Required keys:
#   PRIVATE_KEY             operator wallet (signs every broadcast — bootstrap,
#                           infra deploy, impl deploy, vetting). For live-contract
#                           deploys this MUST be DEPLOY_OPERATOR's key.
#   DEPLOY_OPERATOR         ⚠️ every LIVE canonical address (WalletFactory,
#                           Shrincs*) is a function of this address — sender-
#                           guarded CreateX salts; guard the key (deploy-all-*,
#                           predict-*)
#   DEPLOYER_ADDRESS        bootstrapped Deployer contract address (e.g. the
#                           canonical 0xA1A3990E…) — sunset WOTS+ family only
#   FACTORY_OWNER           WalletFactory initial owner (deploy-all-* only)
#   MAX_FEE                 WalletFactory creation fee in wei (deploy-all-* only)
#   PAYMASTER_OWNER         QuipPaymaster proxy initial owner (deploy-all-* only)
#   SHRINCS_PAYMASTER_OWNER / SHRINCS_VERIFIER_COMMITMENT /
#   SHRINCS_VERIFIER_MAX_SIGNATURES   ShrincsPaymaster init (deploy-all-* only)
#   FACTORY_ADDRESS         existing WalletFactory address (deploy-impl-*, vet-impl-*)
#   IMPLEMENTATION          WOTSPlusImplementation impl address (vet-impl-* only)
#   API_URL_BASE_SEPOLIA    https://… RPC endpoint
#   ETHERSCAN_API_KEY       Etherscan v2 key (used for --verify)

predict-base-sepolia:
	forge script script/PredictAddresses.s.sol --rpc-url base_sepolia

deploy-deployer-base-sepolia:
	forge script script/deprecated/DeployDeployer.s.sol \
	  --rpc-url base_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

deploy-all-base-sepolia:
	FOUNDRY_PROFILE=deploy forge script script/DeployAll.s.sol \
	  --rpc-url base_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

deploy-impl-base-sepolia:
	FOUNDRY_PROFILE=deploy forge script script/deprecated/DeployImplementation.s.sol \
	  --rpc-url base_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

vet-impl-base-sepolia:
	forge script script/VetImplementation.s.sol \
	  --rpc-url base_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast

predict-op-sepolia:
	forge script script/PredictAddresses.s.sol --rpc-url op_sepolia

deploy-deployer-op-sepolia:
	forge script script/deprecated/DeployDeployer.s.sol \
	  --rpc-url op_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

deploy-all-op-sepolia:
	FOUNDRY_PROFILE=deploy forge script script/DeployAll.s.sol \
	  --rpc-url op_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

deploy-impl-op-sepolia:
	FOUNDRY_PROFILE=deploy forge script script/deprecated/DeployImplementation.s.sol \
	  --rpc-url op_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

vet-impl-op-sepolia:
	forge script script/VetImplementation.s.sol \
	  --rpc-url op_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast

# ── Utility Scripts ───────────────────────────────────────────────

fund-deployer:
	npx tsx scripts/fundDeployer.cts

drain-deployer:
	npx tsx scripts/drainDeployer.cts

balance:
	npx tsx scripts/balance.cts
