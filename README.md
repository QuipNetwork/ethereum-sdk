# Quip Network SDK

This project contains the smart contracts and TypeScript SDK for interacting with the Quip Network EVM Smart Contracts.

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

### Deploying Contracts
```shell
npx hardhat run scripts/deploy.ts --network <network_name>
```

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

## Available Networks

- Ethereum Sepolia (`sepolia`)
- Base Sepolia (`sepolia_base`)
- Optimism Sepolia (`sepolia_optimism`)
- Ethereum Mainnet (`mainnet`)
- Base (`base`)
- Optimism (`optimism`)
