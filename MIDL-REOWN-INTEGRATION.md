# Reown AppKit and MIDL.xyz: compatibility and integration options

**Good news: MIDL.xyz already supports multiple Bitcoin wallets—not just Xverse—and a Reown integration is technically feasible but requires custom bridging.** MIDL's own SDK (`@midl-xyz/midl-js`) provides native support for Xverse, Leather, Unisat, and Phantom wallets. If you need Reown AppKit's unified wallet modal experience (especially for multi-chain apps), you can build a custom integration layer that uses Reown for wallet connections while leveraging MIDL's SDK for protocol interactions.

## What Reown AppKit offers for Bitcoin

Reown AppKit (formerly WalletConnect) added **Bitcoin support in v1.6.1** with a dedicated `@reown/appkit-adapter-bitcoin` package. The adapter supports three Bitcoin networks: **mainnet**, **testnet**, and **signet**—imported as `bitcoin`, `bitcoinTestnet`, and `bitcoinSignet` from `@reown/appkit/networks`.

Currently supported Bitcoin wallets include **Xverse, Leather, Phantom, and OKX** as primary integrations, with **Binance Web3 Wallet, Bitget, and Unisat** added through a recent BOB partnership. The adapter exposes four key JSON-RPC methods:

- **`sendTransfer`**: Sign and broadcast Bitcoin transfers to a single recipient
- **`signPSBT`**: Sign Partially Signed Bitcoin Transactions for complex operations
- **`signMessage`**: Sign messages using ECDSA or BIP-322 protocols
- **`getAccountAddresses`**: Retrieve all account addresses for UTXO tracking

One important limitation: not all wallets support every method. Apps may encounter `MethodNotSupportedError` when calling unsupported operations on specific wallets. Additionally, email/social login features available for EVM chains are **not supported** for Bitcoin connections.

## MIDL.xyz is a Bitcoin execution layer, not just a network

MIDL describes itself as a "Bitcoin Abstraction layer" that enables **Solidity smart contract execution natively on Bitcoin without bridging**. Unlike L2 solutions that batch transactions elsewhere, MIDL creates an EVM-like execution environment where validators execute logic and finalize outcomes directly on Bitcoin. Users sign regular Bitcoin transactions and use native BTC—no wrapped tokens or bridges required.

The platform is currently **live on Bitcoin testnet** with mainnet planned. Its architecture works as follows: users create a Bitcoin transaction containing a command and funds, MIDL validators catch and validate the transaction, funds are held in TSS-secured addresses (Threshold Signature Scheme), smart contracts execute in MIDL's environment, and results are finalized on Bitcoin.

### MIDL's JavaScript SDK ecosystem

MIDL provides a complete SDK under the `@midl-xyz` npm scope:

| Package | Purpose |
|---------|---------|
| `@midl-xyz/midl-js-core` | Core utilities for Bitcoin transactions, signing, Rune operations |
| `@midl-xyz/midl-js-react` | React hooks for seamless frontend integration |
| `@midl-xyz/midl-js-connectors` | Wallet connector implementations |
| `@midl-xyz/hardhat-deploy` | Hardhat plugin for deploying Solidity contracts to MIDL |

The core package supports connecting to any Bitcoin network, publishing transactions, signing PSBTs, BIP-322/ECDSA message signing, and **Rune transfers and etching**—a key differentiator for Bitcoin-native asset operations.

### MIDL wallet support is broader than expected

Contrary to the user's assumption, **MIDL supports four major Bitcoin wallets**: Xverse, Leather, Unisat, and Phantom. The `@midl-xyz/midl-js-connectors` package handles wallet integration through standardized connector implementations. For EVM wallet connections (used in MIDL's liquidity features), MetaMask, Rabby, and Rainbow are also supported.

## No existing integration exists—but compatibility is possible

Research found **no direct integrations** between Reown AppKit and MIDL.xyz. Both technologies operate independently with their own wallet connection approaches. MIDL built their own complete SDK (using SatoshiKit internally) rather than integrating with existing wallet connection libraries, prioritizing control over their protocol-specific requirements.

However, technical compatibility exists because:

1. **Overlapping wallet support**: Both Reown and MIDL support Xverse, Leather, and Phantom
2. **Compatible signing capabilities**: Both support PSBT signing and message signing
3. **Standardized Bitcoin operations**: Reown's `signPSBT` output can theoretically be used for MIDL transactions

The key technical challenge is that Bitcoin lacks a universal wallet standard like EVM's EIP-6963. Each wallet (Unisat, Xverse, Leather) has proprietary APIs, making cross-library interoperability non-trivial.

## Three integration approaches for your app

### Approach 1: Use MIDL.js exclusively (recommended for MIDL-focused apps)

If your app primarily interacts with MIDL protocol, use their native SDK directly:

```typescript
// Install packages
// npm install @midl-xyz/midl-js-core @midl-xyz/midl-js-react @midl-xyz/midl-js-connectors

import { useBroadcastTransaction } from "@midl/react";

function MidlTransaction() {
  const { broadcastTransaction } = useBroadcastTransaction();
  
  const handleTransaction = async () => {
    const result = await broadcastTransaction({
      tx: "020000001..." // Your signed transaction
    });
    console.log("Transaction broadcasted:", result);
  };
  
  return <button onClick={handleTransaction}>Execute MIDL Transaction</button>;
}
```

**Pros**: Native support, maintained by MIDL team, full feature access including Runes
**Cons**: Separate wallet connection UI from any EVM chains in your app

### Approach 2: Parallel SDK integration (for multi-chain apps)

Run both Reown AppKit and MIDL.js side-by-side, using Reown for consistent UX and MIDL.js for protocol operations:

```typescript
// Reown setup for wallet connection
import { createAppKit } from '@reown/appkit/react';
import { BitcoinAdapter } from '@reown/appkit-adapter-bitcoin';
import { bitcoin, bitcoinTestnet } from '@reown/appkit/networks';

const bitcoinAdapter = new BitcoinAdapter({ projectId: 'YOUR_PROJECT_ID' });
createAppKit({
  adapters: [bitcoinAdapter],
  networks: [bitcoin, bitcoinTestnet],
  projectId: 'YOUR_PROJECT_ID',
  features: { email: false, socials: [] }
});

// For MIDL-specific operations, use midl-js-core directly
import { /* MIDL utilities */ } from '@midl-xyz/midl-js-core';
```

**Pros**: Unified wallet modal across chains, Reown's polished UX
**Cons**: Two wallet connection states to manage, potential user confusion

### Approach 3: Custom bridge adapter (advanced)

Create a custom adapter that bridges Reown's `BitcoinConnector` interface with MIDL's transaction requirements:

```typescript
import { useAppKitProvider } from "@reown/appkit/react";
import type { BitcoinConnector } from "@reown/appkit-adapter-bitcoin";

function useMidlWithReown() {
  const { walletProvider } = useAppKitProvider<BitcoinConnector>("bip122");
  
  const executeMidlTransaction = async (command: string, amount: string) => {
    // 1. Use Reown provider to get addresses
    const addresses = await walletProvider.getAccountAddresses();
    
    // 2. Construct MIDL-compatible PSBT
    // This requires understanding MIDL's transaction format
    const psbt = constructMidlPsbt(command, amount, addresses);
    
    // 3. Sign with Reown provider
    const signedResult = await walletProvider.signPSBT({
      psbt: psbt,
      signInputs: [{ address: addresses[0].address, index: 0 }],
      broadcast: false
    });
    
    // 4. Submit to MIDL network
    // Use MIDL's broadcast mechanism
    return submitToMidl(signedResult.psbt);
  };
  
  return { executeMidlTransaction };
}
```

**Pros**: Single wallet connection, full control over flow
**Cons**: Requires deep understanding of MIDL's transaction format, maintenance burden

## Technical requirements and architecture recommendations

For a production implementation, consider this architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                      Your Application                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐     ┌──────────────────────────────┐  │
│  │   Reown AppKit   │     │         MIDL.js SDK          │  │
│  │ (Wallet Connect) │     │                              │  │
│  │                  │     │  @midl-xyz/midl-js-core      │  │
│  │ - Wallet Modal   │     │  @midl-xyz/midl-js-react     │  │
│  │ - Multi-chain    │     │  @midl-xyz/hardhat-deploy    │  │
│  │ - signPSBT       │────▶│                              │  │
│  │ - signMessage    │     │  - MIDL transactions         │  │
│  └──────────────────┘     │  - Rune operations           │  │
│                           │  - Smart contract calls      │  │
│                           └──────────────────────────────┘  │
│                                        │                     │
│                                        ▼                     │
│                           ┌──────────────────────────────┐  │
│                           │      MIDL Network            │  │
│                           │  (Testnet / Future Mainnet)  │  │
│                           │  EVM RPC: chainId 777        │  │
│                           └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Key development requirements:**

- **Project ID**: Register at dashboard.reown.com for Reown AppKit
- **MIDL SDK versions**: Currently at v0.0.79 (expect breaking changes)
- **Network**: MIDL is testnet-only; plan for mainnet migration
- **Hardhat config**: Use chainId 777 with `https://evm-rpc.regtest.midl.xyz` for local development

## Conclusion

The most pragmatic path depends on your app's scope. **If building a MIDL-focused Bitcoin app, use MIDL.js directly**—it already supports the wallets you need (Xverse, Leather, Unisat, Phantom) without additional complexity. If building a **multi-chain application** where Bitcoin/MIDL is one of several chains, the parallel SDK approach gives you Reown's polished UX while maintaining MIDL functionality.

The absence of a direct integration means any custom bridging will require ongoing maintenance as both SDKs evolve. Given MIDL is still on testnet (v0.0.79), waiting for their mainnet launch and API stabilization before investing heavily in custom integration work may be prudent. Monitor the [@midl-xyz GitHub organization](https://github.com/midl-xyz/midl-js) for updates on wallet standards adoption and potential WalletConnect/Reown compatibility.