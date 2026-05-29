# Deploying smart contracts on Midl: Complete developer guide

> ⚠️ **Research notes, not a runbook.** This document is pre-deployment exploration of the MIDL ecosystem — much of it was assembled from upstream docs and contains inferred patterns (look for `// Inferred pattern` and similar markers in the code blocks below). It is **not** the canonical procedure for deploying Quip contracts on MIDL.
>
> For the authoritative MIDL deploy path see:
> - **Deploy scripts:** `deploy/midl_regtest/00_deploy_deployer.cts` → `01_deploy_wots.cts` → `02_deploy_factory.cts` → `03_deploy_wallet.cts` → `04_deploy_paymaster.cts` → `05_vet_wallet.cts`. Invoke via `npx hardhat deploy --network midl_regtest --tags <tag>`.
> - **Address registry:** `src/v1/addresses.ts` `NETWORK_ADDRESSES[CHAIN_IDS.MIDL_TESTNET]` and `src/addresses-midl.json` (written by the factory deploy step).
> - **Trust model:** [GOVERNANCE.md](GOVERNANCE.md) covers the factory/paymaster owner posture and the planned migration to on-chain governance.
> - **Deployments status:** [DEPLOYMENTS.md](DEPLOYMENTS.md) for canonical addresses and per-chain status.
>
> Treat the rest of this document as background on the MIDL platform itself — useful for understanding what the deploy scripts above are talking to, not as instructions to copy.

---

**Midl is a Bitcoin execution layer enabling native EVM smart contracts without bridging**—and it's currently in testnet only. Mainnet hasn't launched yet, pending performance validation and security audits. The network uses a unique architecture: users sign regular Bitcoin transactions, and Midl validators execute corresponding EVM logic, committing state back to Bitcoin via Merkle root proofs.

## Deployment configuration for Hardhat/ethers.js

The @midl-xyz/hardhat-deploy plugin provides Midl-specific deployment capabilities. Based on available documentation and npm packages, here's the configuration:

```javascript
// hardhat.config.js
import "@midl-xyz/hardhat-deploy";

module.exports = {
  midl: {
    mnemonic: "your bitcoin mnemonic phrase",
    path: "deployments",
  },
  networks: {
    midl: {
      url: "https://evm-rpc.regtest.midl.xyz",
      chainId: 777,
    },
  },
  etherscan: {
    apiKey: {
      midl: "not-required" // Blockscout typically doesn't require API keys
    },
    customChains: [
      {
        network: "midl",
        chainId: 777,
        urls: {
          apiURL: "https://explorer.regtest.midl.xyz/api", // Inferred pattern
          browserURL: "https://explorer.regtest.midl.xyz"   // Inferred pattern
        }
      }
    ]
  }
};
```

**Confirmed parameters for regtest (testnet):**
- **Chain ID**: 777
- **EVM RPC URL**: `https://evm-rpc.regtest.midl.xyz`
- **Bitcoin RPC URL**: `https://rpc.regtest.midl.xyz/`
- **Native currency**: BTC (regular Bitcoin—no separate gas token)
- **Block explorer**: Blockscout fork (midl-xyz/blockscout repositories on GitHub)

**Not yet publicly available:** Mainnet chain ID, mainnet RPC URLs, and production explorer URLs. These will be released after mainnet launch. The explorer URL pattern likely follows `explorer.[network].midl.xyz` based on the project's infrastructure naming conventions.

## Midl deployment differs from standard Hardhat

The critical difference: Midl deployments use a batched execution model that links to Bitcoin transactions. The deploy script pattern is:

```javascript
// deploy/001_deploy_contract.js
export default async function deploy(hre) {
  await hre.midl.initialize();                    // Initialize Bitcoin connection
  const deployer = await hre.midl.getAddress();   // Get Bitcoin-derived address
  
  await hre.midl.deploy("YourContract", {
    from: deployer,
    args: [100],
  });
  
  await hre.midl.execute();  // Batches operations into a Bitcoin transaction
}
```

This contrasts with standard EVM deployment where `deploy()` immediately broadcasts. On Midl, `execute()` bundles multiple operations and commits them through a Bitcoin transaction—users can execute up to **10 Midl transactions within a single BTC transaction**.

## Dependencies install non-destructively alongside other chains

**Yes, Midl dependencies work alongside other blockchain configurations** like Degen without conflicts or separate branches. The @midl-xyz/hardhat-deploy plugin is explicitly designed to complement standard hardhat-deploy.

```bash
# Install for cross-chain projects
npm install hardhat hardhat-deploy @midl-xyz/hardhat-deploy
npm install @nomiclabs/hardhat-ethers ethers
```

**Multi-chain configuration example:**

```javascript
import "@midl-xyz/hardhat-deploy";
import "hardhat-deploy";

module.exports = {
  midl: {
    mnemonic: process.env.BTC_MNEMONIC,
    path: "deployments",
  },
  networks: {
    // Midl Network
    midl: {
      url: "https://evm-rpc.regtest.midl.xyz",
      chainId: 777,
    },
    // Degen Chain
    degen: {
      url: "https://rpc.degen.tips",
      chainId: 666666666,
      accounts: [process.env.PRIVATE_KEY],
    },
    // Ethereum Mainnet
    ethereum: {
      url: process.env.ETH_RPC,
      accounts: [process.env.PRIVATE_KEY],
    },
  },
  solidity: "0.8.19",
};
```

The same Solidity contracts deploy to both Midl and standard EVM chains without modification—Midl runs a full EVM execution environment. The only difference is deployment mechanics: use `hre.midl.*` methods for Midl, standard `deployments.deploy()` for other chains.

**Recommended project structure for cross-chain:**
```
project/
├── contracts/           # Same contracts for all chains
├── deploy/
│   ├── midl/           # Midl-specific deploy scripts
│   └── evm/            # Standard EVM deploy scripts
└── deployments/        # Network-specific deployment artifacts
```

**Watch for potential conflicts** if using both @midl-xyz/midl-viem and standard viem—ensure explicit import paths. The Midl team forked Ethers, Viem, and Hardhat to add Bitcoin transaction type support, so version management matters for projects using both libraries extensively.

## Bitcoin interaction uses validator consensus, not cryptographic proofs

**Midl does not use STARK proofs, SNARK proofs, or fraud proofs.** The architecture relies on Delegated Proof-of-Stake (DPoS) validator consensus with Threshold Signature Schemes (TSS) for Bitcoin integration. This is fundamentally different from BitVM-style fraud proofs or ZK-rollup validity proofs.

### The transaction flow works like this:

1. **User creates a Bitcoin transaction** sending BTC/Runes to TSS Vaults controlled by validators
2. **User signs "intents"** (Midl dApp transactions) using BTC private keys via BIP322 message signing
3. **User attaches the BTC transaction hash** to their signed intent
4. **Validators acknowledge** the Bitcoin transaction appearing on-chain
5. **Validators execute** corresponding EVM smart contract logic
6. **Validators return** Bitcoin transactions containing results back to users

The whitepaper describes this as: *"To exist on Midl, a tx should always exist on Bitcoin. Users do only BTC txs; Validators execute the logic and reflect the outcome."*

### Technical architecture components

**BTC transaction hash field**: Midl added a new "BTC" transaction type to their forked EVM node that includes a Bitcoin transaction hash field. From their Developer Diary: *"Adding a new type of transaction, a 'BTC' one, and adding a new field that accepts the Bitcoin transaction hash. That's pretty much it."*

**TSS Vaults**: Validators manage threshold signature vaults that control UTXOs. Users send assets to these vaults; validators process the EVM logic and return Bitcoin transactions with results. The TSS approach ensures no single entity controls funds.

**Merkle root commitments**: Validators commit compact Midl state proofs to Bitcoin by storing Merkle roots of Midl blocks. This allows later verification of Midl state against Bitcoin's blockchain.

**UTXO-to-account translation**: The system translates Bitcoin's UTXO model into EVM's account-based model. Validators manage UTXOs at the TSS level while users interact with familiar EVM account balances.

**Runes integration**: Midl supports Bitcoin's Runes asset standard using OP_RETURN data encoding. Wallets need Taproot address generation and Runes indexing capabilities.

### Security model comparison

| Aspect | Midl | BitVM | ZK-Rollups |
|--------|------|-------|------------|
| **Proof type** | Validator consensus (DPoS) | Fraud proofs | STARK/SNARK validity proofs |
| **Trust assumption** | Honest validator majority | 1-of-n honest verifier | Mathematical soundness |
| **Finality** | 1 Bitcoin block + validator confirmation | Multi-week dispute period | Proof generation time |
| **Security basis** | Economic stake (slashing) | Cryptographic fraud proofs | Zero-knowledge cryptography |

Validators face slashing for refusing transactions, prolonged non-participation, invalid execution, or network attacks. The security model relies on economic incentives rather than cryptographic validity proofs.

## Key resources and current limitations

**Official documentation**: js.midl.xyz (JavaScript SDK), midl.xyz/whitepaper.pdf (architecture), github.com/midl-xyz (repositories)

**NPM packages**: `@midl-xyz/hardhat-deploy`, `@midl-xyz/midl-js-core`, `@midl-xyz/midl-viem`, `@midl-xyz/midl-js-react`

**Supported wallets**: Xverse, MetaMask (via BTC Snap), with Ledger planned. Wallets must support secp256k1 signatures, BIP322 message signing, and Taproot addresses for full Runes support.

**Current status**: Midl is live on Bitcoin testnet only. Mainnet launches after performance validation and completed audits. The project raised $2.4M in seed funding led by Draper Associates in July 2025, with 20+ protocols reportedly building on the testnet.

For production deployment, monitor the official channels for mainnet configuration details—chain ID, RPC URLs, and explorer endpoints for the production network haven't been publicly released yet.