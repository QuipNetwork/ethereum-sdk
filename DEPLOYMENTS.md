# Deployments

## V1 Contracts (CREATE2)

All V1 contracts share the same addresses on every deployed chain. Deterministic deployment
via CREATE2 through the Deployer contract with salt `keccak256("QUIP")`.

Compiler: solc 0.8.28+commit.7893614a, EVM paris, optimizer disabled, bytecodeHash=none.

### Addresses

| Contract | Address | Chains |
|----------|---------|--------|
| Deployer | `0xF768b4E4A314C9119587b8Cd35a89bDC228290b5` | Ethereum, Base, Optimism, Degen |
| WOTSPlus | `0x1Ad02caBfc65ed65FDF6da64108f04f71E2e8991` | Ethereum, Base, Optimism, Degen |
| QuipFactory | `0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99` | Ethereum, Base, Optimism, Degen |

### Chains

| Chain | Chain ID | Deployer Method |
|-------|----------|-----------------|
| Ethereum | 1 | CREATE at nonce=1 (Deployer), CREATE2 (WOTSPlus, QuipFactory) |
| Base | 8453 | Same |
| Optimism | 10 | Same |
| Degen | 666666666 | Same |

### Ethereum Mainnet Transactions

| Contract | Block | Tx Hash |
|----------|-------|---------|
| WOTSPlus | 22228373 | `0xb3e6c01c55091f04d3ea9c4a656d3a3038f24cd892439b61e20a3054f892b8a4` |
| QuipFactory | 22228374 | `0x5830a69f7bf7049193a6145306058aaea29249a2da2fdc246d3aaa0011a156eb` |

### Deployment Parameters

- **Deployer**: deployed via `CREATE` at `nonce=1` from a one-time wallet
- **Salt**: `keccak256("QUIP")` = `0xd9fb07cc22ea59a9164c9fbaf3b898b3e6c5190454c06259cf5c99c889dc63f4`
- **QuipFactory constructor**: `(initialOwner=0x4971905B8741BdBe1Ba008f73C28c82DE9D95df9, wotsLibrary=0x1Ad02...)`
- **Linked library**: WOTSPlus at `0x1Ad02caBfc65ed65FDF6da64108f04f71E2e8991`

---

## V2 Deployment Workflow (CREATE3)

Future deployments use CREATE3 through the Deployer. CREATE3 addresses depend only on
the Deployer address and salt (not on bytecode), making them predictable before deployment.

### Per-Contract Salts

Each contract uses a versioned salt: `keccak256("QUIP:<ContractName>:V1")`.

| Contract | Salt Preimage |
|----------|---------------|
| WOTSPlus | `QUIP:WOTSPlus:V1` |
| QuipFactory | `QUIP:QuipFactory:V1` |
| QuipWallet | `QUIP:QuipWallet:V1` |

### Library Linking

QuipWallet depends on the WOTSPlus external library. Since CREATE3 addresses are known
before deployment, the WOTSPlus address can be configured ahead of time.

Forge links libraries at compile time via `foundry.toml`:

```toml
[profile.deploy]
libraries = [
    "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol:WOTSPlus:<WOTS_ADDRESS>"
]
```

The `[profile.deploy]` profile is used for deployment scripts (`FOUNDRY_PROFILE=deploy`).
The default profile is left untouched so `forge test` can auto-deploy libraries.

### Steps

```
1. Predict addresses     forge script script/PredictAddresses.s.sol
2. Configure linking     paste WOTSPlus address into foundry.toml [profile.deploy]
3. Release bytecodes     make release
4. Deploy Deployer       make deploy-deployer
5. Deploy infra          make deploy-all          (WOTSPlus + QuipFactory)
6. Deploy implementation make deploy-impl         (QuipWallet via CREATE3)
7. Vet implementation    make vet-impl            (register on QuipFactory)
```
