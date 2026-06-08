# Quip Dummy Dapp

Single-file static site (`index.html`) that lets anyone with a browser wallet
mint the OP Sepolia dummy tokens (tQ6 ERC-20, NFT ERC-721, multi-token
ERC-1155 ids 1 & 2) to themselves and exercise the `DummyQuipArbitraryCall`
test target (`ping` + `alwaysRevert`). The connected wallet is always both
the signer (pays gas) and the recipient — there is no manual address path,
because any mint requires testnet ETH and only the signer has a balance.

> The folder is still called `faucet/` for historical reasons / to avoid
> breaking any existing Vercel deploy that points at it as the project
> root. Inside the page it presents as "Quip Dummy Dapp".

The page is completely self-contained: no build step, no npm dependencies, no
SDK, no CDN libraries. The four function selectors are computed offline (and
re-verified with `cast sig` in CI / by hand) and the calldata is built with
20-line `pad32` / `encodeUint256` helpers in the inline `<script>` block.

## Local

Just open the file:

```sh
open test-sdk/faucet/index.html
```

Or serve it via any static server (recommended over `file://` because some
wallet extensions reject the `file:` origin):

```sh
npx http-server test-sdk/faucet -p 5173 -c-1
```

Then visit <http://localhost:5173/>.

## Vercel

The simplest deploy is "import the repo, then set Root Directory":

1. New Project → import this Git repo.
2. Framework Preset: **Other** (it's a static HTML file).
3. **Root Directory: `test-sdk/faucet`**.
4. Build Command: leave empty. Output Directory: leave empty (Vercel will just
   serve `index.html` from the root directory).
5. Deploy.

No `vercel.json` is required — Vercel auto-detects a single static `index.html`
and serves it as-is.

## What gets minted

All three contracts are CREATE3-deterministic on OP Sepolia (chainId
`11155420`). Anyone can mint to anyone; there is no Ownable, no allowlist, no
faucet timer. Do not reuse these contracts on any chain you care about.

| Contract                       | Address                                      |
| ------------------------------ | -------------------------------------------- |
| tQ6 — ERC-20 (6 decimals)      | `0x154fA1B00D28a200F1AFA75378d0Ae6735252248` |
| DummyQuip NFT — ERC-721        | `0x7EbC22F6bd6cd7D053e82B5C54D075563C89c65b` |
| DummyQuip Multi-token — 1155   | `0xa1A65346f1c155706c7717Dd8860b4F32c94f9eE` |

## Updating addresses or selectors

If you redeploy the dummies (e.g. v3 with a new mint API), update the
`CONTRACTS` and `SELECTORS` objects at the top of the `<script>` block in
`index.html`. Re-derive any new selectors with:

```sh
cast sig 'mint(address,uint256)'
```
