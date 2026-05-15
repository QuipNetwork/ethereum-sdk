# Quip Network SDK

This project contains the smart contracts and TypeScript SDK for interacting with the Quip Network EVM Smart Contracts.

NOTICE: This project is currently in active development and is not yet ready for production use.

## Prerequisites

- Node.js
- npm, bun, yarn, or other equivalent node package manager
- Environment variables set up in `.env` (see Environment Setup below)

## Environment Setup

Copy `.env.example` to `.env` and fill in:
```shell
ALCHEMY_API_KEY=your_alchemy_key
API_URL_SEPOLIA=your_sepolia_url
API_URL_BASE_SEPOLIA=your_base_sepolia_url
API_URL_OP_SEPOLIA=your_optimism_sepolia_url
API_URL_MAINNET=your_mainnet_url
API_URL_BASE=your_base_url
API_URL_OPTIMISM=your_optimism_url
PRIVATE_KEY=your_wallet_private_key
DEPLOYER_ADDRESS=quip_deployer_contract_address
```

For running addNetwork, additional variables are required (contact Rick):
```shell
DEPLOYER_PRIVATE_KEY=
DEPLOYER_PUBLIC_KEY=
```

## Contract Development

### Testing Contracts
```shell
npx hardhat test
# With gas reporting:
REPORT_GAS=true npx hardhat test
```

### Local Development
```shell
npx hardhat node
```

## Deployment

### Adding New Networks (deploying the Deployer contract)
**Important:** Only authorized personnel should run these commands. Contact Rick first.
```shell
npx hardhat run scripts/addNetwork.ts
npx hardhat run scripts/addNetwork.ts --network sepolia
npx hardhat run scripts/addNetwork.ts --network sepolia_base
npx hardhat run scripts/addNetwork.ts --network sepolia_optimism
```

After deploying, you can drain remaining funds from the wallet to the one owned by PRIVATE_KEY:

```shell
npx hardhat run scripts/drainDeployer.ts
npx hardhat run scripts/drainDeployer.ts --network sepolia
npx hardhat run scripts/drainDeployer.ts --network sepolia_base
npx hardhat run scripts/drainDeployer.ts --network sepolia_optimism
```

### Deploying Contracts
```shell
INITIAL_OWNER=<initial_owner_address> npx hardhat run scripts/deploy.ts --network <network_name>
```

Note that the initial owner address will change the deployment address. 

## SDK Development

### Building the SDK
```shell
bun run build
```

### Testing the SDK
```shell
bun run test
```

### Publishing
```shell
npm publish
```

## Contract Verification

The deploy scripts pass `--verify` to forge by default — Etherscan
verification runs as part of the same `make deploy-all-<chain>` /
`make deploy-impl-<chain>` invocation. Set `ETHERSCAN_API_KEY` (Etherscan
v2 — one key covers mainnet, base, optimism, all their L2 testnets, etc.)
in `.env` and forge handles it via the `[etherscan]` map in `foundry.toml`.

To verify an already-deployed contract independently:

```bash
# WOTSPlus library (no constructor args):
forge verify-contract \
  --rpc-url base_sepolia \
  --chain base_sepolia \
  0x742376ec2A8237Ba46E1ACDDfF315f1Ef25E4C0e \
  @quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol:WOTSPlus

# QuipFactory (constructor: address initialOwner, uint256 maxFee):
forge verify-contract \
  --rpc-url base_sepolia \
  --chain base_sepolia \
  --constructor-args $(cast abi-encode "constructor(address,uint256)" "$FACTORY_OWNER" "$MAX_FEE") \
  0xE567d318819c067c26fC1E44D04beD2b4FE93BCC \
  contracts/QuipFactory.sol:QuipFactory

# QuipPaymaster impl + proxy: similar pattern; see DEPLOYMENTS.md for the
# canonical addresses and salts.
```

See `DEPLOYMENTS.md` for the full canonical address table and per-contract
salt scheme.

## Available Networks

- Ethereum Sepolia (`sepolia`)
- Base Sepolia (`sepolia_base`)
- Optimism Sepolia (`sepolia_optimism`)
- Ethereum Mainnet (`mainnet`)
- Base (`base`)
- Optimism (`optimism`)


## License

Copyright (C) 2024 quip.network

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

See COPYING for the full license text.
