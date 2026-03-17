.PHONY: build test clean format snapshot gas install update release \
       deploy-deployer deploy-wotsplus deploy-factory deploy-all \
       fund-deployer drain-deployer balance

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

# ── Utility Scripts ───────────────────────────────────────────────

fund-deployer:
	npx tsx scripts/fundDeployer.cts

drain-deployer:
	npx tsx scripts/drainDeployer.cts

balance:
	npx tsx scripts/balance.cts
