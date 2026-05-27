# DummyQuip testnet deployments

Record deployed addresses here after running the dummy contract scripts. These contracts are **test-only** — not part of the QuipFactory / QuipWallet production pipeline.

Same dummy address on multiple chains requires the same `DUMMY_QUIP_CREATE3_FACTORY` address on each chain (factory is deployed via normal `CREATE`, not CREATE3).

The active token suite is built on OpenZeppelin v5.6.0-rc.1 (`ERC20` / `ERC721` / `ERC1155` + their `Burnable` extensions; `ERC1155Supply` for per-id supply tracking). The tokens have **no `Ownable` surface** — `mint` is intentionally ungated to keep QA flows friction-free. Earlier hand-rolled support contracts (receivers, spender, arbitrary-call, custom `Owned`) have been moved to [`_archive/`](_archive/) and are no longer deployed by the active scripts.

---

## OP Sepolia (chain 11155420)

| Item | Address | Notes |
| --- | --- | --- |
| `DummyQuipCreate3Factory` | `TBD` | Set as `DUMMY_QUIP_CREATE3_FACTORY` in `.env`. |
| `DummyQuipERC20SixDecimals` | `TBD` | Class: `DummyQuipERC20`; name `DummyQuip ERC20 Six Decimals`; symbol `tQ6`; decimals `6`. |
| `DummyQuipERC20EighteenDecimals` | `TBD` | Class: `DummyQuipERC20`; name `DummyQuip ERC20 Eighteen Decimals`; symbol `tQ18`; decimals `18`. |
| `DummyQuipERC721` | `TBD` | Minimal NFT; name `DummyQuip NFT`; symbol `tQNFT`. |
| `DummyQuipERC1155` | `TBD` | Minimal multi-token; uri `ipfs://dummy-quip-erc1155/{id}.json`. |

---

## Base Sepolia (chain 84532)

| Item | Address | Notes |
| --- | --- | --- |
| `DummyQuipCreate3Factory` | `TBD` | |
| `DummyQuipERC20SixDecimals` | `TBD` | |
| `DummyQuipERC20EighteenDecimals` | `TBD` | |
| `DummyQuipERC721` | `TBD` | |
| `DummyQuipERC1155` | `TBD` | |

---

## Ethereum Sepolia (chain 11155111)

| Item | Address | Notes |
| --- | --- | --- |
| `DummyQuipCreate3Factory` | `TBD` | |
| `DummyQuipERC20SixDecimals` | `TBD` | |
| `DummyQuipERC20EighteenDecimals` | `TBD` | |
| `DummyQuipERC721` | `TBD` | |
| `DummyQuipERC1155` | `TBD` | |

---

## CREATE3 salts

| Label | Salt input string |
| --- | --- |
| `DummyQuipERC20SixDecimals` | `quip.dummy.DummyQuipERC20SixDecimals.v1` |
| `DummyQuipERC20EighteenDecimals` | `quip.dummy.DummyQuipERC20EighteenDecimals.v1` |
| `DummyQuipERC721` | `quip.dummy.DummyQuipERC721.v1` |
| `DummyQuipERC1155` | `quip.dummy.DummyQuipERC1155.v1` |

Because CREATE3 addresses depend only on `(factory, salt)` — **not** on creation code — the salts above lock in the same address on every chain that shares a factory address, even after the underlying token implementations were rewritten on top of OpenZeppelin. If behavior changes in a way that should produce a new address, bump the salt suffix to `.v2` rather than reusing the same salt.
