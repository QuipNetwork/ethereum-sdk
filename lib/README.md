# Deployment Libraries and Utilities

This directory contains shared libraries and utilities for contract deployment.

**Important:** These files are NOT part of the npm package (`@quip.network/ethereum-sdk`). The publishable SDK code is located in the `src/` directory.

## Contents

- `deploy.ts` - Shared deployment utilities for all networks (CREATE2, drain wallet, etc.)
- `midl.ts` - MIDL-specific utilities (address derivation, plugin types, etc.)

## Usage

These utilities are used by:
- `deploy/` - hardhat-deploy scripts for all networks
- `scripts/` - Manual deployment and maintenance scripts

## Architecture

```
lib/
├── deploy.ts     # Network-agnostic deployment helpers
│   ├── EXPECTED_DEPLOYER_NONCE
│   ├── DEPLOYMENT_SALT
│   ├── computeCreate2Address()
│   ├── isContractDeployed()
│   ├── drainWallet()
│   └── isMidlNetwork()
│
└── midl.ts       # MIDL-specific utilities
    ├── MidlHRE interface
    ├── midlDeriveEvmAddress()
    ├── midlGetOperationsAddress()
    ├── midlGetDeployerAddress()
    └── midlInitialize()
```
