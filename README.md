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

Assuming the following is in your addresses.json folder: 

```
Deployer: 0xF768b4E4A314C9119587b8Cd35a89bDC228290b5
WOTSPlus: 0x1Ad02caBfc65ed65FDF6da64108f04f71E2e8991
QuipFactory: 0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99
```

Deployer:

```
npx hardhat verify --network mainnet 0xF768b4E4A314C9119587b8Cd35a89bDC228290b5
npx hardhat verify --network optimism 0xF768b4E4A314C9119587b8Cd35a89bDC228290b5
npx hardhat verify --network base 0xF768b4E4A314C9119587b8Cd35a89bDC228290b5
npx hardhat verify --network degen 0xF768b4E4A314C9119587b8Cd35a89bDC228290b5
...
```

WOTSPlus:

```
npx hardhat verify --network mainnet 0x1Ad02caBfc65ed65FDF6da64108f04f71E2e8991
npx hardhat verify --network degen 0x1Ad02caBfc65ed65FDF6da64108f04f71E2e8991
...
```

QuipFactory:

```
npx hardhat verify --network base 0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99 "0x4971905b8741BDbE1Ba008f73C28C82DE9d95dF9" "0x1Ad02caBfc65ed65FDF6da64108f04f71E2e8991"
npx hardhat verify --network degen 0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99 "0x4971905b8741BDbE1Ba008f73C28C82DE9d95dF9" "0x1Ad02caBfc65ed65FDF6da64108f04f71E2e8991"
...
```

Where `0x4971905b8741BDbE1Ba008f73C28C82DE9d95dF9` is the initial owner address.

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
