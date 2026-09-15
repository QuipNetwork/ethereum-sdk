# Deployments

## Live — V1.0.1 generation (Base mainnet 8453 deployed 2026-08-28; Base Sepolia 84532 + OP Sepolia 11155420 deployed 2026-08-27)

### Base mainnet (8453) — deployed 2026-08-28 from commit `4588879`

Fresh chain, so the whole generation landed directly at `-beta.2` (no
upgrade path fired) at the same addresses as the testnets, after
hashsigs-solidity had deployed the V3/V4 verifier pair. `01_DeployFactory`
block 50544586 (factory impl `0x25f9cea7…c8a8`, proxy `0xf74632d4…89d0`);
`02_DeployShrincs` block 50544701 (wallet impl `0xd942124d…8da6`, paymaster
impl `0x1d4a1536…e0e7`, paymaster proxy `0x36d4ddcc…0c54`, vet
`0xd2c7feea…1815`). All three Shrincs contracts + the factory verified on
Basescan (the two impls via `forge verify-contract` after `--verify` raced
Etherscan's queue).

**Paymaster verifier key.** The proxy was initialized with the index-0
operator key (the testnets' key — a `.env` expansion slip), then rotated the
same day with owner-fiat `rotateStatefulKey` (tx `0x9823103a…019d`, block
50545015) to the **index-1 stateful subkey**; the index-0 stateless half is
carried forward (inert: the paymaster never verifies stateless signatures).
Live: commitment `0x0727577159d5862d456780f62343b8a0b02e89ac084de267ea42288b55c56857`,
epoch 1, budget 4096, 0 used. The sponsor keypair is the graft
`deriveKeyPair({ statefulIndex: 1, statelessIndex: 0, maxSignatures: 4096 })`
(see `scripts/rotate-shrincs-paymaster-key.mjs`). Epoch-0's index-0 tree is
now spent on this paymaster and stays usable on the testnets only. EntryPoint
deposit/stake not yet funded.

**Factory fees** (owner txs, ETH ≈ $2,519 at the time): `setCreationFee`
0.0004 ETH ≈ $1 (tx `0x918c40e7…8179`, block 50545018); `setExecuteFee`
0.000004 ETH ≈ $0.01 (tx `0x25d43d2c…fa2a`, block 50545029). `MAX_FEE`
immutable is 1 ETH. Testnet factories keep both at 0.

### `-beta.2` implementations (spent-tree registries) — testnets upgraded in place 2026-08-28

The Shrincs implementations move to `V1.0.1-beta.2` for the spent-tree
registries fix (a stateful or stateless tree can never be re-installed on a
wallet or paymaster — INVARIANTS §25; the same-key rotation that reset the
leaf bitmap). Storage is ERC-7201 append-only, so **both proxies keep their
addresses**; `02_DeployShrincs` now (a) deploys the two new impls, (b) vets the
wallet impl, and (c) `upgradeToAndCall`s the paymaster proxy in place (owner =
operator on the testnets, no re-init). The upgrade runs no initializer, so the
tree those two proxies installed under `-beta.1` stays absent from the new
registry and the on-chain guard does not bind on it. The "Registry provenance"
bullet in INVARIANTS §25 gives the scope and the operational mitigations. The
`-beta.1` wallet
impl stays vetted (not deprecated). The WalletFactory
code is unchanged, so its impl stays at `-beta.1`. Base mainnet gets the whole
generation fresh at these same addresses (done — see the Base mainnet section
above).

Broadcast 2026-08-28 from commit `4588879` ("bump salts") with
`make deploy-shrincs-<chain>`; four txs
per chain, all in one block, all verified on Etherscan:

- **Base Sepolia (84532)**, block 46054862: wallet impl
  `0x2398d3cb…6cb9b`, vet `0x624dcb67…1954`, paymaster impl `0xcff1d7a2…6dc7`,
  proxy `upgradeToAndCall` `0x55c3044b…1efd`.
- **OP Sepolia (11155420)**, block 48037763: wallet impl `0x806fdc66…bd54`,
  vet `0xcb5eba7e…03e4`, paymaster impl `0x77c526be…0696`, proxy
  `upgradeToAndCall` `0x66a1b279…0174`.

Post-state on both chains: the paymaster proxy's ERC-1967 slot reads
`0x5E4E4003…92d2`, `latestWalletImpl()` is `0x680840c8…4FBC`, and
`getShrincsVerifier()` is unchanged by the upgrade (commitment
`0x538c6eb0…07bf`, epoch 0, budget 4096, 0 used). The paymaster impl runtime
is byte-identical across the two chains; the wallet impl differs only by its
cached EIP-712 chain-id immutables. Receipts under `broadcast/`.

| | Address |
|---|---|
| ShrincsWallet impl (`…:Impl:V1.0.1-beta.2:` ‖ `PROFILE_ID`) | `0x680840c831c6D147404a0e00edA08a5360564FBC` |
| ShrincsPaymaster impl (`…:Impl:V1.0.1-beta.2:` ‖ `PROFILE_ID`) | `0x5E4E4003118a0F8825494D76E86Db2ed654992d2` |
| ShrincsWallet impl `-beta.1` (superseded; still vetted) | `0x076bF15aa48bf12a6D9f48b3b0D79875d4E1e094` |
| ShrincsPaymaster impl `-beta.1` (retired; proxy upgraded away) | `0xD0C56265b942160bb4470077f65123EE34E0Ee93` |

### `-beta.1` (initial deploy)

A **full redeploy of every contract on every chain**. Three things moved at
once: `script/Constants.sol` now pins the **V4** `SHRINCS256sKeccak` verifier
from hashsigs-solidity MR !26 (raw ERC-7913 signatures bound to the full
public-key commitment; `VERSION_TAG` v4; oak-02…15 audit fixes), which both
Shrincs implementations bake in as an immutable; the WalletFactory code changed
since the 2026-08-03 deploy (e3r commitment-bound deploy salts, deploy
authorization, codehash deprecation); and the V1.0.0 generation below was a
production-testing deployment, so rather than `upgradeToAndCall` its proxies in
place, the proxies move too and every wallet address derives fresh from the new
factory. CREATE3 ignores initcode and `CreateXHelpers` idempotent-skips an
occupied address, so every V1.0.0 / V1.0.0-beta preimage is retired. Impls
start at `V1.0.1-beta.1` rather than `-beta` because
`QUIP:ShrincsPaymaster:Impl:V1.0.1-beta:` was already consumed on the testnets
(see the retired table) and the suffix is kept uniform across impls.

Proxies carry a plain version (`V1.0.1` — a proxy is just a proxy);
implementations carry `V1.0.1-beta.1`, bumped npm-style (`-beta.2`, …) on any
relocation within the generation.

Deployed from commit `2342d9b` on 2026-08-27 on **Base Sepolia (84532)**
(`01_DeployFactory` block 46041802, `02_DeployShrincs` block 46042001) and
**OP Sepolia (11155420)** (`01` block 48025406, `02` block 48025453);
receipts under `broadcast/`. Every address landed exactly where
`PredictAddresses` said, and the runtime code is byte-identical across the two
chains except ShrincsWallet's cached EIP-712 immutables (domain separator +
chain id). On both chains the paymaster proxy was initialized with the
operator's freshly derived V4/HD verifier key — commitment
`0x538c6eb0aa2a22531068031057e7baac0b1d5dea46a8473bbe96c0aad4e807bf`,
`maxSignatures` 4096, derivation index 0; EntryPoint deposit/stake are not
funded yet. The verifier pair is live on both testnets — `cast code` runtime
hashes `0xe9319929…` (SHRINCS V4) and `0xe8d1cd07…` (SPHINCSPlusC V3) match
hashsigs-solidity's `DEPLOYMENTS.md` (OP Sepolia pair deployed 2026-08-27 from
the hashsigs-solidity checkout at `672cb90`, same operator), and the live
`VERSION_TAG` / `PROFILE_TAG` read back as v4 / `shrincs-256s-keccak`. Base
mainnet still needs hashsigs-solidity to deploy `SPHINCSPlusC256sKeccak:V3.0`
then `SHRINCS256sKeccak:V4.0` first; then `01_DeployFactory` →
`02_DeployShrincs` land at the same addresses (`02` refuses until the pinned
verifier hosts the expected `PROFILE_TAG`). Explorer source verification:
everything verified on OP Sepolia except the ShrincsWallet impl (Etherscan
rejected the automatic bytecode match — immutables; re-run with
`forge verify-contract` if needed).

| | Address |
|---|---|
| WalletFactory impl (`QUIP:WalletFactory:Impl:V1.0.1-beta.1`) | `0x77622e199DfF602f937fC5E5eB6479aE4b18161F` |
| **WalletFactory proxy** (`QUIP:WalletFactory:Proxy:V1.0.1`) | `0xA2B2F71456a799FCf4EF7A3111c4B96b3e928cc8` |
| ShrincsWallet impl (`…:Impl:V1.0.1-beta.1:` ‖ `PROFILE_ID`) | `0x076bF15aa48bf12a6D9f48b3b0D79875d4E1e094` |
| ShrincsPaymaster impl (`…:Impl:V1.0.1-beta.1:` ‖ `PROFILE_ID`) | `0xD0C56265b942160bb4470077f65123EE34E0Ee93` |
| **ShrincsPaymaster proxy** (`QUIP:ShrincsPaymaster:Proxy:V1.0.1`) | `0x430c8c89492E3541e141148Dd7a7D6dD432e5890` |
| SHRINCS256sKeccak verifier V4.0 (external, pinned) | `0xF2f9E6D692da41b089c3c261c41509669eEc5567` |
| SPHINCSPlusC256sKeccak V3.0 (its stateless delegate) | `0xe52707C5D76E2F7c3314cF3dcc340eB9BbAE3864` |

`src/v1/shrincs/addresses.ts`, `src/v1/addresses.json`,
`src/v1/shrincs/tests/addresses.test.ts` and
`deployments/bytecode/WalletFactory.sol/0x77622e19….json` describe this generation. The
dep is pinned to `672cb90`, the head of the open MR (now targeting `main`);
re-pin if it is rebased before merge. Withdraw the V1.0.0 paymaster's EntryPoint deposit/stake once the
new one is live.

## Live — V1.0.0 generation (CreateX-direct, sender-guarded) — superseded by the V1.0.1 redeploy above

The go-forward lineage: WalletFactory (UUPS) + SHRINCS family, deployed by
`script/01_DeployFactory.s.sol` → `script/02_DeployShrincs.s.sol`. Every
address is a function of (CreateX, `CANONICAL_OPERATOR`, salt preimage) — see
`script/Constants.sol` for the salts — and is identical on every chain the
operator deploys to. Verify locally with `make predict-addresses` (the operator
is pinned — no env vars needed).

**Live on Base mainnet (8453) as of 2026-08-03**, all five contracts verified on
Basescan. As of 2026-08-14 the factory and wallet halves are live at the same
canonical addresses on Base Sepolia (84532) and OP Sepolia (11155420) too; the
ShrincsPaymaster remains mainnet-only.

| | Base mainnet | Base Sepolia | OP Sepolia |
|---|---|---|---|
| WalletFactory impl | ✅ | ✅ | ✅ |
| WalletFactory proxy | ✅ | ✅ | ✅ |
| ShrincsWallet impl (vetted, `latestWalletImpl`) | ✅ | ✅ | ✅ |
| ShrincsPaymaster impl + proxy | ✅ | — | — |
| SHRINCS256sKeccak verifier | ✅ | ✅ | ✅ |

The WalletFactory *impl* predates this generation on the two testnets: its salt
never moved and its bytecode never referenced the verifier, so it kept its
address across the generation boundary. The prior generation also remains on
those chains — see *Superseded generation*.

| | Address |
|---|---|
| CANONICAL_OPERATOR | `0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26` |
| WalletFactory impl (`V1.0.0-beta`; retired) | `0x738456Bc546b887764bD6C462FDA6d49bBcA0c9f` |
| **WalletFactory proxy** (`V1.0.0`; retired — wallets derived from it stay with it) | `0xdCD90563B912f82D2f23d5c7988B3Fec2da63471` |
| ShrincsWallet impl (`V1.0.0-beta`; retired) | `0x33d3949117c8Bba7A3637C96a564a817E00c5aE0` |
| ShrincsPaymaster impl (`V1.0.0-beta`; retired) | `0x995bDB6768F25822Faafb2c9b6Ad7Cf10CB6EEc3` |
| **ShrincsPaymaster proxy** (`V1.0.0`; retired) | `0x077C06913777777DfABf951a5A0F8CA665764ac9` |
| SHRINCS256sKeccak verifier (external; V2 — superseded by the pending V4 pin) | `0xE6F2970bA30d59e8288b7007bA755828372457c3` |


> The verifier is deployed by hashsigs-solidity's own CreateX scripts (its
> `DEPLOYMENTS.md`), not this repo — the Shrincs implementations pin it as an
> immutable, and `02_DeployShrincs` refuses to deploy unless the pinned
> address hosts the expected scheme (`PROFILE_TAG`). It is **live on Base
> mainnet (8453), Base Sepolia (84532) and OP Sepolia (11155420)** together with
> its stateless delegate `SPHINCSPlusC256sKeccak` at
> `0x97B3726F44e3B7521199CE4e0fC160A32A597d31`. The testnet copies were deployed
> on 2026-08-14 and are byte-identical to the mainnet ones.
> `dependencies/@quip.network/hashsigs-solidity` is pinned to rev `dd6fa9e`, the
> commit that build came from, so the artifact we compile matches the bytes on
> chain.

### Deployed transactions (Base mainnet, 8453)

Broadcast by `CANONICAL_OPERATOR` through CreateX's permissioned mode, so these
addresses were reachable by no other account. Two blocks, one per script.

| Artifact | Address | Tx | Block | Gas |
|---|---|---|---|---|
| WalletFactory impl | `0x738456Bc546b887764bD6C462FDA6d49bBcA0c9f` | `0x6803e47686aaec35f4c159e720b383743609d9f868a8f918433b83127c8cd64d` | 49485171 | 1,786,028 |
| WalletFactory proxy | `0xdCD90563B912f82D2f23d5c7988B3Fec2da63471` | `0xdc65e84bb3be3bb35edca6a3008a72768c42a23454fd568a83005d2f3a03cec9` | 49485171 | 195,629 |
| ShrincsWallet impl | `0x33d3949117c8Bba7A3637C96a564a817E00c5aE0` | `0x0bf64af71bd74bd501a35e5261588260c466a578c83669156f8f171060167b1e` | 49485205 | 3,883,195 |
| ↳ `vetImplementation` | (call on the factory) | `0x17bc8fd942bc364da2cefa5df73aea247463407b38a2c7ad245a189d71ee4813` | 49485205 | 101,824 |
| ShrincsPaymaster impl | `0x995bDB6768F25822Faafb2c9b6Ad7Cf10CB6EEc3` | `0x54a63c3f55b630baa857d6d6d5062309f5eb0a237eb8bb2bea424ebed7b747e6` | 49485205 | 1,742,504 |
| ShrincsPaymaster proxy | `0x077C06913777777DfABf951a5A0F8CA665764ac9` | `0x9a54e7f927fd39ceabf3191682e121df020bc23bb3c3d1fe96d79111b82478f6` | 49485205 | 251,696 |

Total 7,960,876 gas. Block 49485171 (`01_DeployFactory`) and 49485205
(`02_DeployShrincs`), 2026-08-03 12:21–12:22 UTC. All five contracts are
verified on Basescan.

> ⚠️ Do NOT read the per-transaction mapping out of
> `broadcast/*/8453/run-latest.json` — its `additionalContracts` field pairs
> hashes with the wrong addresses here, because every CreateX deploy is a `CALL`
> to the singleton rather than a `CREATE`. The table above was reconstructed
> from on-chain receipt logs and cross-checked against contract sizes.

Installed verifier state at deploy (`getShrincsVerifier()`): commitment
`0xd2f83c7986abe791212b6d399929aa7f17977d059d6d5d047bf3010072fbae72`,
`keyVersion` 0, `maxSignatures` 4096 (the hashsigs keygen ceiling),
`statefulLeavesUsed` 0.

> ⚠️ **Post-deploy state — not yet production-ready.** Both the factory and the
> paymaster are still owned by the deploy EOA and have NOT been handed over to a
> post-quantum wallet, so a single ECDSA key can rotate the verifier, drain the
> deposit, and upgrade either implementation. The paymaster has no EntryPoint
> deposit and no stake, so it cannot sponsor anything and conformant bundlers
> will reject it. `creationFee` and `executeFee` are both 0.

### Deployed transactions (Base Sepolia 84532, OP Sepolia 11155420)

Same operator, same CreateX permissioned mode, on 2026-08-14. `01_DeployFactory`
broadcast a single transaction per chain: the WalletFactory impl was already at
its canonical address from the previous generation, so the idempotent path
skipped it and only the proxy went out. The wallet impl followed later the same
day via `script/DeployShrincsWallet.s.sol` — deploy + vet, no paymaster.

| Chain | Artifact | Tx | Block | Gas |
|---|---|---|---|---|
| 84532 | WalletFactory proxy | `0x0b7901fea5afa722592a9070326205c2c22b4a97056282aef337f7d527e84ce8` | 45464746 | 195,629 |
| 84532 | ShrincsWallet impl | `0xf9fee3c664f885e5d801647be07a8a52fc4ace95a3fdbbf8dcdbdd2e8a3728d5` | 45481568 | 3,883,195 |
| 84532 | ↳ `vetImplementation` | `0x8762fda46fd388c924e8539f2839bb8a378af0f50983b12416b8cb6f47abecb1` | 45481568 | 101,824 |
| 11155420 | WalletFactory proxy | `0xe147e53e3f8b104172f762cfe59abef0a20a38357cac8d3f90fb3644e6f28b0a` | 47447636 | 195,629 |
| 11155420 | ShrincsWallet impl | `0x6bb1c19b198957824b546b2795eb81f673dc6160aefc689cb7770c690174d350` | 47464469 | 3,883,195 |
| 11155420 | ↳ `vetImplementation` | `0x2494be8c719167fd3ede9f1695f850ec22f3f9180b2fb91034edd8a9824be192` | 47464469 | 101,824 |

Post-deploy state on both testnets: factory `owner()` and `latestWalletImpl()`
are the operator and `0x33d3949117c8Bba7A3637C96a564a817E00c5aE0`,
`getVettedCodeCount()` is 1, `MAX_FEE()` is 1e18.

> The ShrincsWallet **codehash differs per chain** even though the source and
> compiler settings are identical — OpenZeppelin's `EIP712` caches the chain id
> and the derived domain separator as immutables, so the deployed bytes are
> chain-scoped by construction. Blanking the immutable windows makes all three
> chains byte-identical to a local build. Vetting is keyed on codehash, which is
> why each chain must vet its own impl; the address is the same everywhere
> because CREATE3 ignores creation code.

> No ShrincsPaymaster on either testnet. `02_DeployShrincs` would deploy one, but
> it installs a stateful SHRINCS sponsorship key at `initialize`, and the key in
> `.env` is the one already installed on mainnet. Sharing a stateful hash-based
> key across chains is unsafe: each paymaster tracks its own leaf bitmap from
> zero, and `_domainSeparator()` folds in `block.chainid`, so the same leaf index
> signs *different* messages on two chains — a one-time-signature disclosure that
> leaks that leaf's key. Generate a separate key per testnet before deploying a
> paymaster there. `script/DeployShrincsWallet.s.sol` exists for exactly this
> case: the wallet half without the paymaster.

### Superseded generation (Base Sepolia 84532, OP Sepolia 11155420)

Live since 2026-07-29 and left in place. hashsigs moved its own deploys onto
sender-guarded CreateX salts, which relocated every verifier; because both
Shrincs implementations bake the verifier in as an immutable, their bytecode
changed and their salts had to move with it. The proxies and the wallet impl
were re-versioned at the same time so the whole set reads as one generation.

| | Address (superseded) |
|---|---|
| WalletFactory proxy | `0x6de121F7cc8b310aDBc957425B97e1C8dfcE3BE5` |
| ShrincsWallet impl | `0xb84a596A6fB567FC4634b4f49212410D1193140e` |
| ShrincsPaymaster impl | `0x71c976A2FCed1B5e9C171BAf029a12fdaf391f49` |
| ShrincsPaymaster proxy | `0xd258BA8ddEACe7A74184f368B7FDb55DDa53DcC5` |
| SHRINCS256sKeccak verifier | `0x9154dA0BA19600C543a8c5ed1B1c44af415B5688` |
| ShrincsPaymaster pair, pre-bundle-rework | `0xfc5b4E75CA03c260255523DbbF56e93F9cbB5c59` (impl), `0xE38420930EBD214FE8FEb403dd66F4887AEF76E8` (proxy) |

Every preimage behind those addresses is permanently occupied on those chains —
**never reuse one**. Two consequences worth stating plainly:

- **Wallet addresses move.** The factory proxy is the permanent factory
  identity: wallets bake it in as an immutable and CREATE3 wallet addressing
  derives from it. A new factory proxy means every user wallet derives to a new
  address. Wallets already deployed on the testnets stay with the old factory.
- **The testnets now carry both generations.** As of 2026-08-14 the current
  generation's factory and wallet halves live alongside the superseded set on
  both chains (the pinned verifier was deployed there first, which is what made
  it possible). They are still not a mirror of mainnet — no ShrincsPaymaster —
  and the chain-invariance property holds *within* a generation, not across
  them.

Withdraw the retired paymasters' EntryPoint deposits/stake; nothing should point
at them.

## v1.1 — canonical addresses (CREATE3 via the v1 Deployer)

All v1.1 contracts share the same addresses on every chain where the v1
Deployer is bootstrapped. Live on Base Sepolia as of 2026-06-03; other
CREATE3 chains require a v1.1 deploy to materialize. Computed before any
deploy is broadcast — run `make predict-addresses` to see them locally
with no env vars and no RPC.

| Contract | Address |
|---|---|
| Deployer (v1, reused) | `0xA1A3990Ea898123e4B107D0A2f614232bE428Ef1` |
| WOTSPlus | `0x7837b85Fa4D31a5af8FD28e66b18f156F66C3723` |
| QuipFactory | `0xd175378EC511e56BbffcC802375C6ad7d892c083` |
| QuipWallet (impl) | `0xDe0Eb22871dC0F51B0C625c9a4ff9e8D1ac96d64` |
| QuipPaymaster (impl) | `0x557453653005e6F35EA3265733f3F1c4643A1627` |
| QuipPaymaster (proxy, canonical) | `0xC4209cD353CF7B1dbBf6F6B4d08bC5461aC7E145` |

> The QuipPaymaster proxy is the user-facing paymaster address; the impl
> behind it is intentionally inert (`_disableInitializers()` runs in its
> constructor).
>
> The Deployer keeps its v1 salt — bumping the contract-host's address
> would break the cross-chain pin without a corresponding redeploy
> everywhere. Only the downstream contracts roll forward.

> ⚠️ **The WOTS+ family is sunset** (July 2026). `WOTSPlus`, `QuipWallet`, and
> `QuipPaymaster` above are the deprecated WOTS+ family — the deployed artifacts
> remain live and fully functional, but the source now lives under
> `contracts/deprecated/` (deploy scripts under `script/deprecated/`; SDK surface
> under the `./deprecated/*` npm subpaths). SHRINCS (`ShrincsWallet` +
> `ShrincsPaymaster`) is the go-forward family.

> ⚠️ **The go-forward factory (UUPS, renamed `WalletFactory`) supersedes the
> address above — and deploys through a new mechanism.** The factory became
> UUPS-upgradeable (impl + ERC-1967 proxy, like the paymaster), and in July
> 2026 the contract was renamed `QuipFactory` → **`WalletFactory`** and the
> deploy path moved to **CreateX-direct with sender-guarded salts** (see
> below) on fresh `V1.0.0-beta` salts (the interim `V2` salt strings were
> never broadcast, so no deployed address was orphaned). The V1.1 salt is
> retired because CREATE3 ignores initcode, so reusing it would resolve to
> the old non-upgradeable factory on chains where it exists. The new proxy
> address (the permanent factory identity — wallets bake it in, CREATE3
> wallet addressing derives from it) is recorded in the **Live** table at the
> top of this file. The `0xd175…` V1.1 factory above remains on Base Sepolia
> as a retired artifact under its historical name.

### Salts

**Live contracts** — sender-guarded CreateX preimages. The deployed address
is a function of (CreateX, `CANONICAL_OPERATOR`, preimage); only the operator
can consume the salt. The Shrincs *implementation* preimages append
`SHRINCSParams.PROFILE_ID` (= `keccak256("shrincs-256s-keccak")`, the
verifier's `PROFILE_TAG()`) so an impl built against a different
cryptographic scheme structurally lands at a different address.

**One scheme, two suffixes**, applied uniformly:

- **proxies → `V1.0.1`** — the generation's public identity, plain version (a
  proxy is just a proxy); code changes happen *under* it via UUPS.
- **implementations → `V1.0.1-beta.1.N`** — the churning half, replaced whenever
  the code or the pinned verifier changes; bumped npm-style (`-beta`, `-beta.1`,
  …) on every relocation within the generation.

Salt strings are **opaque preimages**: only uniqueness matters. `V1.0.0` is not
"newer than" `V1.0.0-beta` — they name different roles, not an ordering.

| Contract | Salt preimage |
|---|---|
| WalletFactory impl (UUPS) | `QUIP:WalletFactory:Impl:V1.0.1-beta.1` |
| WalletFactory proxy (canonical) | `QUIP:WalletFactory:Proxy:V1.0.1` |
| ShrincsWallet impl | `QUIP:ShrincsWallet:Impl:V1.0.1-beta.1:` ‖ `PROFILE_ID` |
| ShrincsPaymaster impl | `QUIP:ShrincsPaymaster:Impl:V1.0.1-beta.1:` ‖ `PROFILE_ID` |
| ShrincsPaymaster proxy | `QUIP:ShrincsPaymaster:Proxy:V1.0.1` |

Retired and permanently occupied — **never reuse**:

| Contract | Salt preimage | Occupied on |
|---|---|---|
| WalletFactory impl (pre-e3r code) | `QUIP:WalletFactory:Impl:V1.0.0-beta` | Base mainnet, Base Sepolia, OP Sepolia |
| WalletFactory proxy (V1.0.0 generation) | `QUIP:WalletFactory:Proxy:V1.0.0` | Base mainnet, Base Sepolia, OP Sepolia |
| ShrincsPaymaster proxy (V1.0.0 generation) | `QUIP:ShrincsPaymaster:Proxy:V1.0.0` | Base mainnet |
| ShrincsWallet impl (V2 verifier) | `QUIP:ShrincsWallet:Impl:V1.0.0-beta:` ‖ `PROFILE_ID` | Base mainnet, Base Sepolia, OP Sepolia |
| ShrincsPaymaster impl (V2 verifier) | `QUIP:ShrincsPaymaster:Impl:V1.0.0-beta:` ‖ `PROFILE_ID` | Base mainnet |

On Base Sepolia / OP Sepolia only:

| | Retired preimage |
|---|---|
| WalletFactory proxy | `QUIP:WalletFactory:Proxy:V1.0.0-beta` |
| ShrincsWallet impl | `QUIP:ShrincsWallet:V1.1:` ‖ `PROFILE_ID` |
| ShrincsPaymaster impl | `QUIP:ShrincsPaymaster:Impl:V1.0.1-beta:` ‖ `PROFILE_ID`, and `…:Impl:V1.1:` ‖ `PROFILE_ID` |
| ShrincsPaymaster proxy | `QUIP:ShrincsPaymaster:Proxy:V1.0.1-beta`, and `…:Proxy:V1.1` |

The WalletFactory *impl* preimage is unchanged and intentionally so: its
bytecode never referenced the verifier, so it keeps its address across the
generation boundary.

**Sunset WOTS+ era** — unguarded salts (`keccak256(preimage)`) consumed
through the deprecated Deployer; addresses depend only on (Deployer, salt).

| Contract | Salt preimage |
|---|---|
| Deployer (via CreateX, unchanged) | `QUIP:Deployer:V1` |
| WOTSPlus | `QUIP:WOTSPlus:V1.1` |
| QuipFactory (retired, non-upgradeable) | `QUIP:QuipFactory:V1.1` |
| QuipWallet impl | `QUIP:QuipWallet:V1.1` |
| QuipPaymaster impl | `QUIP:QuipPaymaster:Impl:V1.1` |
| QuipPaymaster proxy | `QUIP:QuipPaymaster:Proxy:V1.1` |

### CreateX-direct (live contracts)

Live contracts (`WalletFactory`, `ShrincsWallet`, `ShrincsPaymaster`)
deploy straight through the **CreateX** singleton at
`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed` (pre-deployed on every chain
via Nick's-method presigned tx) — no in-repo deploy contract, no bootstrap
step. `script/CreateXHelpers.sol` implements the scheme; the release/predict
tooling (`scripts/release.ts`, `script/PredictAddresses.s.sol`) mirrors it.

Salt scheme (CreateX's `_parseSalt` layout, MsgSender + no-crosschain mode):

```
rawSalt     = bytes20(DEPLOY_OPERATOR) ‖ 0x00 ‖ bytes11(keccak256(preimage))
guardedSalt = keccak256(bytes32(uint160(DEPLOY_OPERATOR)) ‖ rawSalt)
address     = CREATE3(CreateX, guardedSalt)
```

- **Sender-guarded (squat-proof):** the raw salt embeds the operator's
  address, so CreateX only accepts it from `msg.sender == DEPLOY_OPERATOR`.
  Nobody else can consume a canonical salt on a fresh chain. (CREATE3
  ignores initcode — under the old permissionless Deployer, anyone could
  have deployed arbitrary code at a canonical address first, and the
  idempotent skip would have silently accepted it.)
- **A wrong caller does NOT revert.** CreateX's `_parseSalt` sees leading
  bytes matching neither `msg.sender` nor `address(0)`, falls through to the
  PERMISSIONLESS branch, and deploys *successfully* at a different address.
  The canonical address stays untouched — that is the squat-proofing — but
  the failure is silent, which is why `_createXDeploy` checks the broadcaster
  itself. Verified against the real singleton by
  `test_senderGuard_strangerLandsElsewhere_canonicalUntouched`.
- **Chain-invariant:** the 21st byte `0x00` opts out of CreateX's chainid
  binding, so the same (operator, preimage) lands at the same address on
  every chain. `0x01` would bind `block.chainid` and give per-chain
  addresses; `CreateXHelpers._rawSalt` writes the `0x00` explicitly and
  `_assertSaltLayout` refuses anything else.
- **API asymmetry to remember:** `CreateX.deployCreate3` consumes the RAW
  salt (and guards internally); address *prediction* consumes the GUARDED
  salt — offline via solady's `CREATE3.predictDeterministicAddress(guardedSalt,
  CreateX)` (CreateX uses the same CREATE3 proxy initcode), no RPC needed.

> ⚠️ **Every live canonical address is a function of `DEPLOY_OPERATOR`.**
> The operator key must sign each canonical deploy on each chain, forever —
> losing it means losing the ability to materialize the canonical addresses
> on new chains. Guard that key accordingly.

### The operator is pinned, not configured

`DeployConstants.CANONICAL_OPERATOR` (mirrored in
`src/v1/internal/createxSalts.ts`) hard-codes
`0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26`. `DEPLOY_OPERATOR` is still read
from the environment, but must equal the pin or the run aborts.

This closes a silent failure. `require(vm.addr(PRIVATE_KEY) == DEPLOY_OPERATOR)`
only proves the env var and the key agree with *each other* — a stale or
mistyped operator plus its matching key predicts, deploys, and self-asserts a
perfectly consistent result, at an address nothing in this file publishes.

**Changing the operator re-derives every live address.** It is a four-part edit
that must land together, or the SDK will publish addresses that do not exist:

1. `DeployConstants.CANONICAL_OPERATOR` (`script/Constants.sol`)
2. `CANONICAL_OPERATOR` (`src/v1/internal/createxSalts.ts`)
3. the address tables in this file and the pins in `src/v1/shrincs/addresses.ts`
4. `make release` to regenerate `src/v1/addresses.json`

`test_publishedRegistry_matchesDerivation` and the SDK's `addresses.test.ts`
fail until all four agree.

> ⚠️ **A Safe/multisig operator is not a drop-in.** The broadcaster check reads
> `vm.addr(PRIVATE_KEY)`, and it works only because the EOA calls CreateX
> *directly*. Route the deploy through a Safe and CreateX sees the Safe as
> `msg.sender` while the salt still embeds the EOA — the permissionless branch,
> a different address. Moving the operator behind a contract means embedding the
> **Safe's** address in the salt, which changes every canonical address.

### Gates that run before any broadcast

| Gate | Catches |
|---|---|
| `DEPLOY_OPERATOR == CANONICAL_OPERATOR` | stale/mistyped operator — the silent wrong-address deploy |
| `vm.addr(PRIVATE_KEY) == DEPLOY_OPERATOR` | wrong signer; CreateX would take the permissionless branch without reverting |
| `_assertSaltLayout` | salt bytes 0–19 not the operator, or byte 20 not `0x00` (chain-invariance) |
| local prediction `==` `ICreateX.computeCreate3Address(guardedSalt)` | drift between our mirror of `_guard` and the singleton we are about to call |
| identity view calls on occupied addresses | stale or foreign code adopted by the idempotent skip — `MAX_FEE()` for the factory impl, `FACTORY()`/`SHRINCS_VERIFIER()` for the Shrincs impls, a non-zero ERC-1967 slot for both proxies |
| `deployed == expected` | any post-broadcast branch divergence |

Runtime codehash is deliberately **not** pinned: all three live artifacts carry
constructor-set immutables (`MAX_FEE`, `SHRINCS_VERIFIER`, `FACTORY`), so the
codehash is a function of the deploy params and no static pin is knowable. The
identity view calls read those same immutables directly instead. The codehash is
logged on the skip path for forensics only.

### Deployer bootstrap (sunset WOTS+ era)

The historical flow for the WOTS+ family, kept only to reproduce the
deployed artifacts (`contracts/deprecated/Deployer.sol`,
`script/deprecated/DeployDeployer.s.sol`). The Deployer *hosts* solady
CREATE3, so it can't deploy itself — it was bootstrapped via CreateX on an
**unguarded** salt: `keccak256("QUIP:Deployer:V1")` has its first 20 bytes
as random hash output (neither `msg.sender` nor `address(0)`), so CreateX's
guard hits the fallback branch `guardedSalt = keccak256(abi.encode(salt))`.
Any funded wallet can broadcast the bootstrap, and the address is the same
on every chain — but that permissionlessness is exactly the squatting
exposure the live sender-guarded scheme closes. Once the Deployer exists on
a chain, the WOTS+-era contracts deploy through it via solady CREATE3.

### Library linking

`QuipWallet` (the sunset WOTS+ implementation, `contracts/deprecated/wots/`)
calls into the `WOTSPlus` library at runtime — its compiled
bytecode contains a placeholder that must be replaced with WOTSPlus's
address before deploy. (`WalletFactory` no longer links WOTSPlus: the
WOTS+ decoupling removed its last dependency, so factory bytecode is
link-free.) Foundry handles the wallet linking via the
`[profile.deploy]` profile in `foundry.toml`:

```toml
[profile.deploy]
libraries = [
    "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol:WOTSPlus:0x7837b85Fa4D31a5af8FD28e66b18f156F66C3723"
]
```

Only the sunset WOTS+ scripts (under `script/deprecated/`) touch
`QuipWallet` bytecode and run under `FOUNDRY_PROFILE=deploy`; the live
numbered entrypoints link no libraries and need no profile.

### Deployment workflow

The live flow is two numbered scripts, run in order (both idempotent —
re-runs skip anything already deployed/vetted):

```
0. Predict addresses     make predict-addresses
                         # No RPC and no env vars needed — the operator is
                         # pinned (CANONICAL_OPERATOR). Every row must match
                         # the Live table above; a DEPLOY_OPERATOR that
                         # disagrees with the pin aborts instead of printing
                         # a plausible wrong address set.

1. Deploy factory        make deploy-factory-<chain>
                         # script/01_DeployFactory.s.sol: WalletFactory impl
                         # + ERC-1967 proxy via CreateX. PRIVATE_KEY must be
                         # DEPLOY_OPERATOR's key (sender-guarded salts).
                         # Requires DEPLOY_OPERATOR, FACTORY_OWNER, MAX_FEE.

2. Deploy Shrincs        make deploy-shrincs-<chain>
                         # script/02_DeployShrincs.s.sol: ShrincsWallet impl
                         # (vetted; becomes latestWalletImpl) + ShrincsPaymaster.
                         # Locates the factory at its canonical derived address
                         # only (no env override) and verifies it is an
                         # operator-owned ERC-1967 proxy before broadcasting.
                         # Requires SHRINCS_* in .env.
```

Ops utility: `IMPLEMENTATION=0x... make vet-impl-<chain>` — the factory
owner whitelists an already-deployed wallet impl (any family; idempotent).

Sunset WOTS+ family (optional, frozen under `script/deprecated/`):
`make deploy-deployer-<chain>` bootstraps the legacy `Deployer`, then
`make deploy-impl-<chain>` deploys a WOTSPlusImplementation through it
(`FOUNDRY_PROFILE=deploy`; per-chain targets set it automatically).
Note that vetting a WOTS+ impl AFTER the Shrincs deploy would flip
`latestWalletImpl` back to WOTS+ — the intended default is Shrincs.

`<chain>` is `base-sepolia`, `op-sepolia`, or `base` (mainnet); see Makefile for
the full list of per-chain targets. Step 1 is a no-op on a chain whose factory
is already live (both scripts are idempotent per-contract), so rolling only the
paymaster onto an existing chain is just step 2.

**Base mainnet** additionally has dry-run targets — `make dryrun-factory-base`
and `make dryrun-shrincs-base` — which simulate against a fork without
`--broadcast`, so nothing is sent on-chain. They pass `--sender
$(DEPLOY_OPERATOR)` but no `--private-key` flag; the scripts still read
`PRIVATE_KEY` from your `.env` to simulate the operator's broadcast and assert
`vm.addr(PRIVATE_KEY) == DEPLOY_OPERATOR`, so `PRIVATE_KEY` must be set. Run both
before either `deploy-*-base` and confirm the printed addresses match the Live
table above. `API_URL_BASE` must be a keyed provider: a
public endpoint times out mid-simulation. The sunset WOTS+ targets are
deliberately not mirrored for mainnet.

### Required environment variables

Put these in a project-local `.env` (Makefile auto-loads it). All
addresses below are examples — substitute your actual operator wallets.

```bash
# Chain RPC + Etherscan
API_URL_BASE_SEPOLIA=https://base-sepolia.g.alchemy.com/v2/<key>
ETHERSCAN_API_KEY=<your-etherscan-v2-key>      # works across all chains

# Wallet — one key for every step. The Makefile auto-loads .env, so
# `make deploy-factory-base-sepolia` etc. pick this up without any further
# arguments. For live-contract deploys PRIVATE_KEY MUST be the key of
# DEPLOY_OPERATOR (sender-guarded salts revert for any other sender).
PRIVATE_KEY=0x...

# ⚠️ The operator EVERY live canonical address derives from
# (WalletFactory, ShrincsWallet, ShrincsPaymaster). This key must sign
# each canonical deploy on each chain, forever — losing it means losing
# the ability to materialize the canonical addresses on new chains.
DEPLOY_OPERATOR=0x...

# Deploy-time owners / params
FACTORY_OWNER=0x...                            # controls vetImplementation
MAX_FEE=1000000000000000000                     # wallet creation fee cap (wei),
                                               # 1e18. MUST stay 1e18: it is a
                                               # constructor immutable of the
                                               # WalletFactory impl, and every live
                                               # chain already hosts the 1e18 build.
                                               # 01_DeployFactory asserts
                                               # MAX_FEE() == $MAX_FEE and aborts on
                                               # a mismatch.
SHRINCS_PAYMASTER_OWNER=0x...                  # 02_DeployShrincs
SHRINCS_VERIFIER_PUBLIC_KEY=0x...              # 02_DeployShrincs — abi-encoded
                                               # SHRINCS.PublicKey bundle from
                                               # gen-shrincs-paymaster-verifier.mjs;
                                               # initialize derives the commitment
                                               # + leaf budget from it on-chain.
                                               # ONE bundle per chain (HD network
                                               # level = chain id, index = epoch);
                                               # never reuse across chains.

# Sunset WOTS+ family only
DEPLOYER_ADDRESS=0xA1A3990Ea898123e4B107D0A2f614232bE428Ef1
PAYMASTER_OWNER=0x...                          # QuipPaymaster (WOTS+ era)

# Per-release (deploy-impl-* / vet-impl-* ONLY — the live deploy scripts
# derive the canonical factory address and accept no override)
FACTORY_ADDRESS=0x...
IMPLEMENTATION=0x...                           # filled in after deploy-impl
```

---

## v0.1.x — historical (CREATE2 via custom DeployDeployer at nonce=1)

`@quip.network/ethereum-sdk@0.1.7` and earlier (now vendored at `src/deprecated/v0`, npm subpath `./deprecated/v0`).
Deployer was bootstrapped via plain CREATE at nonce 1 from a fresh EOA;
downstream contracts used `keccak256("QUIP")` as the salt with no
per-contract versioning.

| Contract | Address |
|---|---|
| Deployer (v0) | `0xF768b4E4A314C9119587b8Cd35a89bDC228290b5` |
| WOTSPlus (v0) | `0x1Ad02caBfc65ed65FDF6da64108f04f71E2e8991` |
| QuipFactory (v0) | `0x4a5A444F3B12342Dc50E34f562DfFBf0152cBb99` |

Salt: `keccak256("QUIP")` = `0xd9fb07cc22ea59a9164c9fbaf3b898b3e6c5190454c06259cf5c99c889dc63f4`.
Live on Ethereum, Base, Optimism, Degen as of `0.1.7`.

The corresponding committed release bytecode lives under
`deployments/bytecode-v0-historical/` (archived; not consumed by any v1
script).
