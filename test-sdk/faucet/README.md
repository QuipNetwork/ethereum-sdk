# Quip Dummy Dapp

Single-file static site (`index.html`) that lets anyone with a browser wallet
mint the **Base Sepolia** dummy tokens (tQ6 ERC-20, NFT ERC-721, multi-token
ERC-1155 ids 1 & 2) to themselves and exercise the `DummyQuipArbitraryCall`
test target (`ping` + `alwaysRevert`). The connected wallet is always both
the signer (pays gas) and the recipient — there is no manual address path,
because any mint requires testnet ETH and only the signer has a balance.

> The folder is still called `faucet/` for historical reasons / to avoid
> breaking any existing Vercel deploy that points at it as the project
> root. Inside the page it presents as "Quip Dummy Dapp".

The page is completely self-contained: no build step, no npm dependencies, no
SDK, no CDN libraries. The function selectors are computed offline (and
re-verified with `cast sig` in CI / by hand) and the calldata is built with
20-line `pad32` / `encodeUint256` helpers in the inline `<script>` block.

## Previous OP Sepolia version

The frozen-at-deploy snapshot of the OP Sepolia version (with hardcoded
OP Sepolia addresses, RPC, and explorer) is kept verbatim at:

```
test-sdk/_archive/faucet-op-sepolia/
```

It still works as-is if you switch a wallet to OP Sepolia and open it in a
browser. Useful as a reference, but not deployed anywhere.

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

All contracts are CREATE3-deterministic on Base Sepolia (chainId `84532`).
Anyone can mint to anyone; there is no `Ownable`, no allowlist, no faucet
timer. Do not reuse these contracts on any chain you care about.

| Contract                       | Address                                       |
| ------------------------------ | --------------------------------------------- |
| `DummyQuipCreate3Factory`      | `0xAA68B21c8225EbB6F580886664d1F7690bDB0c52`  |
| tQ6 — ERC-20 (6 decimals)      | `0x983f05beDC54c1a7F76CdfE48169987a0aF86705`  |
| DummyQuip NFT — ERC-721        | `0xABc9fd3C1bE3E3FFEF6634075459D06D6C3F6be4`  |
| DummyQuip Multi-token — 1155   | `0x1d14B57155ba680e7a8bd1b9630ad1dDf6C31b8D`  |
| `DummyQuipArbitraryCall`       | `0x961b7fedAba6e2915D68D122BFb9f7265E42E200`  |

A second 18-decimals ERC-20 (`tQ18`) was also deployed at
`0xf52f779c1518a7169Bfa70D5f89De8C8806E31Cf` for parity with OP Sepolia but is
not surfaced in the dapp UI.

## Deploying to Base Sepolia

Prerequisites:

- `PRIVATE_KEY_BASE_SEPOLIA` in `.env` (separate operator key from the
  default `PRIVATE_KEY`; see `.env` for security notes).
- `API_URL_BASE_SEPOLIA` in `.env` (Alchemy / public Base Sepolia RPC).
- Funded Base Sepolia ETH on the key's derived address.

End-to-end:

```sh
# 1. Bootstrap the CREATE3 factory (one-time per chain).
make deploy-dummy-create3-base-sepolia
# → copy the printed factory address into .env as
#   DUMMY_QUIP_CREATE3_FACTORY_BASE_SEPOLIA=0x...

# 2. Sanity-print the predicted dummy addresses (no broadcast).
make predict-dummy-base-sepolia

# 3. Deploy all five dummy contracts (idempotent — skips already-deployed
#    salts so it's safe to re-run after a partial broadcast).
make deploy-dummies-base-sepolia
```

After the deploy, open `index.html` and paste the four addresses into the
`CONTRACTS` object near the top of the inline `<script>` block, flipping
each `deployed: false` to `deployed: true`.

## Updating addresses or selectors

If you redeploy the dummies (e.g. v3 with a new mint API), update the
`CONTRACTS` and `SELECTORS` objects at the top of the `<script>` block in
`index.html`. Re-derive any new selectors with:

```sh
cast sig 'mint(address,uint256)'
```
