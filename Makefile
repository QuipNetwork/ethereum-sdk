.PHONY: build test clean format snapshot gas install update release \
       deploy-deployer deploy-wotsplus deploy-factory deploy-all \
       deploy-impl vet-impl predict-addresses \
       fund-deployer drain-deployer balance \
       storage-layout-snapshot storage-layout-check

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
	forge script script/DeployDeployer.s.sol --rpc-url $(RPC_URL) --private-key $(DEPLOYER_PRIVATE_KEY) --broadcast

deploy-wotsplus:
	forge script script/DeployWOTSPlus.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

deploy-factory:
	forge script script/DeployQuipFactory.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

deploy-all:
	forge script script/DeployAll.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --verify

deploy-impl:
	FOUNDRY_PROFILE=deploy forge script script/DeployImplementation.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

vet-impl:
	forge script script/VetImplementation.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

predict-addresses:
	forge script script/PredictAddresses.s.sol

# ── Utility Scripts ───────────────────────────────────────────────

fund-deployer:
	npx tsx scripts/fundDeployer.cts

drain-deployer:
	npx tsx scripts/drainDeployer.cts

balance:
	npx tsx scripts/balance.cts
