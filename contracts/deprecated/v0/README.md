# V0 contracts (archived)

The original QuipWallet / QuipFactory / Deployer trio that shipped with
`@quip.network/ethereum-sdk` 0.1.x. This directory is a **source archive**:
the files are byte-identical to the `v0.1.7` tag (the last commit that built
and deployed them) and are deliberately **not compiled** (`skip` in
`foundry.toml`), **not linted** (`.solhintignore`) and **not formatted**
(`.prettierignore`).

Why not compile: the sources import `@quip.network/hashsigs-solidity` 0.1.x
through the hardhat/npm remapping of the old toolchain. This repository pins
hashsigs-solidity 0.2.0 through soldeer and builds with solc 0.8.33 + `via_ir`,
so any artifact produced here would not match what is on chain. The live
bytecode is pinned separately.

| Need | Where |
|---|---|
| Deployed bytecode, keyed by address | `deployments/bytecode-v0-historical/` |
| Addresses, salt, chains | `DEPLOYMENTS.md`, section "v0.1.x — historical" |
| ABIs, typechain types, SDK | `src/deprecated/v0/` (npm subpath `./deprecated/v0`) |
| Hardhat tests and scripts | tag `v0.1.7`, `test/` and `scripts/` |

Do not confuse this with `contracts/deprecated/wots/`, which is the **V1**
WOTS+ family (`WOTSPlusImplementation`, sunset July 2026). V0 predates it and
shares only the WOTS+ dependency.
