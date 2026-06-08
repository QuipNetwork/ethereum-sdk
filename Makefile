.PHONY: build test clean format lint lint-fix snapshot gas install update release \
       deploy-deployer deploy-wotsplus deploy-factory deploy-all \
       deploy-impl vet-impl predict-addresses \
       predict-base-sepolia deploy-deployer-base-sepolia deploy-all-base-sepolia \
       deploy-impl-base-sepolia vet-impl-base-sepolia \
       predict-op-sepolia deploy-deployer-op-sepolia deploy-all-op-sepolia \
       deploy-impl-op-sepolia vet-impl-op-sepolia \
       deploy-dummy-create3 deploy-dummies predict-dummies deploy-dummy-erc20s \
       deploy-dummy-create3-op-sepolia predict-dummy-op-sepolia deploy-dummies-op-sepolia \
       deploy-dummy-erc20s-op-sepolia \
       deploy-dummy-create3-base-sepolia predict-dummy-base-sepolia deploy-dummies-base-sepolia \
       deploy-dummy-erc20s-base-sepolia \
       deploy-dummy-create3-sepolia predict-dummy-sepolia deploy-dummies-sepolia \
       deploy-dummy-erc20s-sepolia \
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
# Snapshot the QuipWallet ERC-7201 namespace layout (`WOTSPlusStorage.Layout`)
# via the test-only probe contract `QuipWalletLayoutProbe`. ERC-7201 namespaced
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
STORAGE_LAYOUT_FIXTURE := test/fixtures/QuipWallet.storageLayout.json
STORAGE_LAYOUT_NORMALIZE := walk(if type == "object" and has("astId") then del(.astId) else . end) \
	| walk(if type == "string" then gsub("t_struct\\((?<n>[^)]+)\\)\\d+_storage"; "t_struct(\(.n))_storage") else . end) \
	| .types |= with_entries(.key |= sub("t_struct\\((?<n>[^)]+)\\)\\d+_storage"; "t_struct(\(.n))_storage"))

storage-layout-snapshot:
	forge inspect QuipWalletLayoutProbe storageLayout --json \
		| jq '$(STORAGE_LAYOUT_NORMALIZE)' > $(STORAGE_LAYOUT_FIXTURE)
	@echo "✅ Wrote $(STORAGE_LAYOUT_FIXTURE)"

storage-layout-check:
	@forge inspect QuipWalletLayoutProbe storageLayout --json \
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
	forge build && npm run copy-abi && tsc -p tsconfig.build.json && npm run copy-assets

# ── Deploy (requires PRIVATE_KEY, RPC_URL env vars) ──────────────

deploy-deployer:
	forge script script/DeployDeployer.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

deploy-wotsplus:
	forge script script/DeployWOTSPlus.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

deploy-factory:
	FOUNDRY_PROFILE=deploy forge script script/DeployQuipFactory.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

deploy-all:
	FOUNDRY_PROFILE=deploy forge script script/DeployAll.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --verify

deploy-impl:
	FOUNDRY_PROFILE=deploy forge script script/DeployImplementation.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

vet-impl:
	forge script script/VetImplementation.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

predict-addresses:
	forge script script/PredictAddresses.s.sol

# ── Per-chain deploy convenience targets ──────────────────────────
# Each target maps to a [rpc_endpoints] alias in foundry.toml and reads
# its env vars from .env. Required keys:
#   PRIVATE_KEY             operator wallet (signs every broadcast — bootstrap,
#                           infra deploy, impl deploy, vetting)
#   DEPLOYER_ADDRESS        bootstrapped Deployer contract address (e.g. the
#                           canonical 0xA1A3990E… when bootstrapped via CreateX)
#   FACTORY_OWNER           QuipFactory initial owner (deploy-all-* only)
#   MAX_FEE                 QuipFactory creation fee in wei (deploy-all-* only)
#   PAYMASTER_OWNER         QuipPaymaster proxy initial owner (deploy-all-* only)
#   FACTORY_ADDRESS         existing QuipFactory address (deploy-impl-*, vet-impl-*)
#   IMPLEMENTATION          QuipWallet impl address (vet-impl-* only)
#   API_URL_BASE_SEPOLIA    https://… RPC endpoint
#   ETHERSCAN_API_KEY       Etherscan v2 key (used for --verify)

predict-base-sepolia:
	forge script script/PredictAddresses.s.sol --rpc-url base_sepolia

deploy-deployer-base-sepolia:
	forge script script/DeployDeployer.s.sol \
	  --rpc-url base_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

deploy-all-base-sepolia:
	FOUNDRY_PROFILE=deploy forge script script/DeployAll.s.sol \
	  --rpc-url base_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

deploy-impl-base-sepolia:
	FOUNDRY_PROFILE=deploy forge script script/DeployImplementation.s.sol \
	  --rpc-url base_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

vet-impl-base-sepolia:
	forge script script/VetImplementation.s.sol \
	  --rpc-url base_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast

# ── Production deploy: Optimism Sepolia ──────────────────────────
# Same env vars as the Base Sepolia variants; uses `op_sepolia` RPC alias
# from foundry.toml ([rpc_endpoints] op_sepolia = "$(API_URL_OP_SEPOLIA)").
# Etherscan v2 chain `op_sepolia` (chain 11155420) is already wired up in
# foundry.toml [etherscan]; --verify will use $(ETHERSCAN_API_KEY).

predict-op-sepolia:
	forge script script/PredictAddresses.s.sol --rpc-url op_sepolia

deploy-deployer-op-sepolia:
	forge script script/DeployDeployer.s.sol \
	  --rpc-url op_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

deploy-all-op-sepolia:
	FOUNDRY_PROFILE=deploy forge script script/DeployAll.s.sol \
	  --rpc-url op_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

deploy-impl-op-sepolia:
	FOUNDRY_PROFILE=deploy forge script script/DeployImplementation.s.sol \
	  --rpc-url op_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify

vet-impl-op-sepolia:
	forge script script/VetImplementation.s.sol \
	  --rpc-url op_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast

# ── DummyQuip testnet deploy (QA contracts only) ────────────────
# Separate from QuipFactory / DeployAll. Requires PRIVATE_KEY and RPC_URL.
# After deploy-dummy-create3-*, set DUMMY_QUIP_CREATE3_FACTORY in .env.
# Optional: DUMMY_QUIP_OWNER (defaults to vm.addr(PRIVATE_KEY)).
# Use VERIFY= to skip Etherscan verification.

VERIFY ?= --verify

DUMMY_FORGE_FLAGS := --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast $(VERIFY) -vvvv
ifneq ($(strip $(ETHERSCAN_API_KEY)),)
DUMMY_FORGE_FLAGS += --etherscan-api-key $(ETHERSCAN_API_KEY)
endif

deploy-dummy-create3:
	forge script script/dummy_contracts/DeployDummyQuipCreate3Factory.s.sol $(DUMMY_FORGE_FLAGS)

predict-dummies:
	forge script script/dummy_contracts/PredictDummyQuipDummies.s.sol --rpc-url $(RPC_URL) -vvvv

deploy-dummies:
	forge script script/dummy_contracts/DeployDummyQuipDummies.s.sol $(DUMMY_FORGE_FLAGS)

deploy-dummy-erc20s:
	forge script script/dummy_contracts/DeployDummyQuipERC20s.s.sol $(DUMMY_FORGE_FLAGS)

# OP Sepolia — uses the default PRIVATE_KEY (leaked, but already bound to
# this chain's deploys) and the OP-pinned CREATE3 factory address.
#
# Overrides are passed as `$(MAKE) target VAR=val` (command-line args), NOT as
# `VAR=val $(MAKE) target` (env vars). Both forms set VAR in the child make,
# but the child also does `include .env` which sets VAR as a Makefile variable
# — and Makefile-defined values outrank environment values. Command-line args,
# however, beat Makefile assignments, so this is the form that actually wins.
deploy-dummy-create3-op-sepolia:
	$(MAKE) deploy-dummy-create3 \
	  RPC_URL=$(API_URL_OP_SEPOLIA)

predict-dummy-op-sepolia:
	$(MAKE) predict-dummies \
	  RPC_URL=$(API_URL_OP_SEPOLIA) \
	  DUMMY_QUIP_CREATE3_FACTORY=$(DUMMY_QUIP_CREATE3_FACTORY_OP_SEPOLIA)

deploy-dummies-op-sepolia:
	$(MAKE) deploy-dummies \
	  RPC_URL=$(API_URL_OP_SEPOLIA) \
	  DUMMY_QUIP_CREATE3_FACTORY=$(DUMMY_QUIP_CREATE3_FACTORY_OP_SEPOLIA)

deploy-dummy-erc20s-op-sepolia:
	$(MAKE) deploy-dummy-erc20s \
	  RPC_URL=$(API_URL_OP_SEPOLIA) \
	  DUMMY_QUIP_CREATE3_FACTORY=$(DUMMY_QUIP_CREATE3_FACTORY_OP_SEPOLIA)

# Base Sepolia — uses a separate, gitignored operator key (PRIVATE_KEY_BASE_SEPOLIA)
# and the Base-pinned CREATE3 factory address.
deploy-dummy-create3-base-sepolia:
	$(MAKE) deploy-dummy-create3 \
	  RPC_URL=$(API_URL_BASE_SEPOLIA) \
	  PRIVATE_KEY=$(PRIVATE_KEY_BASE_SEPOLIA)

predict-dummy-base-sepolia:
	$(MAKE) predict-dummies \
	  RPC_URL=$(API_URL_BASE_SEPOLIA) \
	  DUMMY_QUIP_CREATE3_FACTORY=$(DUMMY_QUIP_CREATE3_FACTORY_BASE_SEPOLIA)

deploy-dummies-base-sepolia:
	$(MAKE) deploy-dummies \
	  RPC_URL=$(API_URL_BASE_SEPOLIA) \
	  PRIVATE_KEY=$(PRIVATE_KEY_BASE_SEPOLIA) \
	  DUMMY_QUIP_CREATE3_FACTORY=$(DUMMY_QUIP_CREATE3_FACTORY_BASE_SEPOLIA)

deploy-dummy-erc20s-base-sepolia:
	$(MAKE) deploy-dummy-erc20s \
	  RPC_URL=$(API_URL_BASE_SEPOLIA) \
	  PRIVATE_KEY=$(PRIVATE_KEY_BASE_SEPOLIA) \
	  DUMMY_QUIP_CREATE3_FACTORY=$(DUMMY_QUIP_CREATE3_FACTORY_BASE_SEPOLIA)

deploy-dummy-create3-sepolia:
	RPC_URL=$(API_URL_SEPOLIA) $(MAKE) deploy-dummy-create3

predict-dummy-sepolia:
	RPC_URL=$(API_URL_SEPOLIA) $(MAKE) predict-dummies

deploy-dummies-sepolia:
	RPC_URL=$(API_URL_SEPOLIA) $(MAKE) deploy-dummies

deploy-dummy-erc20s-sepolia:
	RPC_URL=$(API_URL_SEPOLIA) $(MAKE) deploy-dummy-erc20s

# ── Utility Scripts ───────────────────────────────────────────────

fund-deployer:
	npx tsx scripts/fundDeployer.cts

drain-deployer:
	npx tsx scripts/drainDeployer.cts

balance:
	npx tsx scripts/balance.cts
