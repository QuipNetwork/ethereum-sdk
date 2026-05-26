# DummyQuip testnet deployments

Record deployed addresses here after running the dummy contract scripts. These contracts are **test-only** — not part of the QuipFactory / QuipWallet production pipeline.

Same dummy address on multiple chains requires the same `DUMMY_QUIP_CREATE3_FACTORY` address on each chain (factory is deployed via normal `CREATE`, not CREATE3).

---

## OP Sepolia (chain 11155420)

| Item | Address | Notes |
| --- | --- | --- |
| `DummyQuipCreate3Factory` | `TBD` | Set as `DUMMY_QUIP_CREATE3_FACTORY` in `.env`. |
| `DummyQuipERC20SixDecimals` | `TBD` | Class: `DummyQuipERC20`; name `DummyQuip ERC20 Six Decimals`; symbol `tQ6`; decimals `6`. |
| `DummyQuipERC20EighteenDecimals` | `TBD` | Class: `DummyQuipERC20`; name `DummyQuip ERC20 Eighteen Decimals`; symbol `tQ18`; decimals `18`. |
| `DummyQuipERC20Spender` | `TBD` | Approval / `transferFrom` testing. |
| `DummyQuipPaymentReceiver` | `TBD` | Payable native-token receiver. |
| `DummyQuipNonPayableReceiver` | `TBD` | Native sends should fail. |
| `DummyQuipRevertingReceiver` | `TBD` | Receive/fallback/explicit call reverts. |
| `DummyQuipERC721` | `TBD` | Minimal NFT; name `DummyQuip NFT`; symbol `tQNFT`; faucet cap `10`. |
| `DummyQuipERC1155` | `TBD` | Minimal multi-token; faucet cap `100` per id. |
| `DummyQuipArbitraryCall` | `TBD` | Records inbound calls and can forward arbitrary calls via `execute`. |

---

## Base Sepolia (chain 84532)

| Item | Address | Notes |
| --- | --- | --- |
| `DummyQuipCreate3Factory` | `TBD` | |
| `DummyQuipERC20SixDecimals` | `TBD` | |
| `DummyQuipERC20EighteenDecimals` | `TBD` | |
| `DummyQuipERC20Spender` | `TBD` | |
| `DummyQuipPaymentReceiver` | `TBD` | |
| `DummyQuipNonPayableReceiver` | `TBD` | |
| `DummyQuipRevertingReceiver` | `TBD` | |
| `DummyQuipERC721` | `TBD` | |
| `DummyQuipERC1155` | `TBD` | |
| `DummyQuipArbitraryCall` | `TBD` | |

---

## Ethereum Sepolia (chain 11155111)

| Item | Address | Notes |
| --- | --- | --- |
| `DummyQuipCreate3Factory` | `TBD` | |
| `DummyQuipERC20SixDecimals` | `TBD` | |
| `DummyQuipERC20EighteenDecimals` | `TBD` | |
| `DummyQuipERC20Spender` | `TBD` | |
| `DummyQuipPaymentReceiver` | `TBD` | |
| `DummyQuipNonPayableReceiver` | `TBD` | |
| `DummyQuipRevertingReceiver` | `TBD` | |
| `DummyQuipERC721` | `TBD` | |
| `DummyQuipERC1155` | `TBD` | |
| `DummyQuipArbitraryCall` | `TBD` | |

---

## CREATE3 salts

| Label | Salt input string |
| --- | --- |
| `DummyQuipERC20SixDecimals` | `quip.dummy.DummyQuipERC20SixDecimals.v1` |
| `DummyQuipERC20EighteenDecimals` | `quip.dummy.DummyQuipERC20EighteenDecimals.v1` |
| `DummyQuipERC20Spender` | `quip.dummy.DummyQuipERC20Spender.v1` |
| `DummyQuipPaymentReceiver` | `quip.dummy.DummyQuipPaymentReceiver.v1` |
| `DummyQuipNonPayableReceiver` | `quip.dummy.DummyQuipNonPayableReceiver.v1` |
| `DummyQuipRevertingReceiver` | `quip.dummy.DummyQuipRevertingReceiver.v1` |
| `DummyQuipERC721` | `quip.dummy.DummyQuipERC721.v1` |
| `DummyQuipERC1155` | `quip.dummy.DummyQuipERC1155.v1` |
| `DummyQuipArbitraryCall` | `quip.dummy.DummyQuipArbitraryCall.v1` |

If behavior changes in a way that should produce a new deployment, bump the salt suffix to `.v2` rather than reusing the same salt/address.
