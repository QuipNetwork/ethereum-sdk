# test-sdk

Self-contained operator smoke scripts that exercise the deployed Quip
Network stack on OP Sepolia using the v1 TypeScript SDK from `src/v1/`.

These are **operator smoke tests**, not unit tests — they require funded
EOAs on OP Sepolia and produce real on-chain transactions. They live
outside `src/v1/tests/` (the SDK's Anvil-based Jest suite) precisely so
they can't be accidentally picked up by `npm test` and burn real ETH.

> **Hardcoded by design.** Every value the scripts need (RPC URL,
> private keys, contract addresses, quantum secrets, vault IDs) is
> hardcoded in `config.ts`. The scripts deliberately do **not** read
> from `.env` or any other ambient config — `test-sdk/` is meant to be
> runnable from a fresh checkout with nothing but `npm install` having
> been run. There is no `state.json`; idempotency comes from querying
> `factory.quips(eoa, vaultId)` on chain. Every key in `config.ts` is
> testnet-only material — never reuse on mainnet.

---

## Files

| File | What it does |
|---|---|
| `config.ts` | All hardcoded constants — chain, RPC, EOAs, contract addresses, WOTS+ seeds. |
| `clients.ts` | Per-EOA factory: viem `publicClient` + `walletClient` (with `nonceManager`) + `QuipSigner` keyed off the EOA's `quantumSecret`. |
| `createWallets.ts` | One-shot: funds wallet 2 if empty, then deploys a `QuipWallet` proxy for each EOA via `factory.deployLatestWalletProxy(...)`. Idempotent — skips wallets that already exist on chain. |
| `transferERC20.ts` | One-shot: tops up wallet 1's Quip wallet with tQ6 if low (direct EOA → ERC20 mint), then calls `wallet.execute(payload)` via `QuipWalletClient.executeWithPayload(...)` to send 10 tQ6 to wallet 2's Quip wallet. Re-runnable — head transaction key rotates on chain each call. |

---

## Usage

```bash
# 0. (one-time) install deps
npm install

# 1. fund wallet 2 (if needed) + mint a Quip wallet for each test EOA
npx tsx test-sdk/createWallets.ts

# 2. (optionally repeatable) transfer 10 tQ6 from wallet 1's Quip wallet
#    to wallet 2's Quip wallet, signed with a fresh WOTS+ key each call
npx tsx test-sdk/transferERC20.ts
```

Expected output of step 2 on a successful run:

```
=== test-sdk / transferERC20 ===
...
Before:
  wallet-1 Quip (0xD2dA…64eB) tQ6: 1000 tQ6
  wallet-2 Quip (0x81D7…0022) tQ6: 0 tQ6

Submitting wallet.execute(...) with WOTS+ signature...
  → tx hash: 0x…
  → status: success

After:
  wallet-1 Quip (0xD2dA…64eB) tQ6: 990 tQ6
  wallet-2 Quip (0x81D7…0022) tQ6: 10 tQ6

Transfer succeeded: 10 tQ6 moved.
```

---

## Why `tsx` and not the compiled `dist/`

`tsx` runs TypeScript source directly with esbuild — no separate compile
step, no `dist/`. We pull SDK symbols from `src/v1/...` source files
directly so a single edit to the SDK is immediately visible to these
scripts without `npm run build` first. The trade-off (slower cold start,
strictly Node-only) is fine for one-off operator scripts.

---

## Gotchas hit while wiring this up

If you're modifying these scripts (or writing new ones in the same
style), the following were non-obvious and cost real debugging time:

### 1. viem's nonce manager is opt-in

Back-to-back transactions from the same EOA inside one Node process
fail with `replacement transaction underpriced` because viem refetches
the nonce from the RPC each call, and a freshly mined tx isn't
immediately reflected in `eth_getTransactionCount`. Fix: attach the
process-wide `nonceManager` singleton from `viem/nonce` when building
the account:

```ts
import { nonceManager } from "viem/nonce";
const account = privateKeyToAccount(pk, { nonceManager });
```

This is wired up once in `clients.ts:makeClients` — every EOA gets it.

### 2. EIP-55 checksums are validated at runtime

viem rejects mis-cased hex addresses with `Address "0x…" is invalid` —
even though every consumer of an `Address` only cares about the lower-
case bytes. Always use `cast to-check-sum-address 0x…` to derive the
canonical EIP-55 form before pasting an address into `config.ts`.

### 3. `QuipWalletClient` accepts an `Account` object, not just a string

The SDK constructor types its 6th argument as `Address` (a hex string),
which on Anvil works because Anvil exposes `eth_sendTransaction` for
the test accounts it manages. On a hosted RPC (Alchemy/Infura/etc.)
that method is unsupported and you get
`Unsupported method: eth_sendTransaction`. Pass the full viem `Account`
object instead (cast as `Address`) so viem routes through
`eth_sendRawTransaction` with local signing:

```ts
const w = new QuipWalletClient(
  signer, vaultId, walletAddress, publicClient, walletClient,
  eoaAccount as unknown as Address,  // <-- not eoaAccount.address
  chainId
);
```

### 4. Pin post-write `eth_call`s to the receipt's `blockNumber`

Hosted RPCs have a read-after-write window of a few hundred ms where
`eth_call` at `"latest"` still returns the pre-tx state even though
`waitForTransactionReceipt` has already resolved. For balance-delta
assertions, read at the exact block the tx mined in:

```ts
const receipt = await wallet.executeWithPayload(...);
const balance = await publicClient.readContract({
  ...,
  blockNumber: receipt.blockNumber,
});
```

We hit this on both the post-mint and post-execute reads in
`transferERC20.ts`.

---

## Repo health notes — `EntryPointV07.ts` ABI stub

While wiring up these scripts we discovered the SDK's TypeScript build
fails out-of-the-box because `src/v1/index.ts` and
`src/v1/walletClient.ts` import from `src/v1/abi/EntryPointV07.js`, but
that file was never produced — `scripts/copy-abi.js` only knows about
the four Quip-owned contracts (Deployer, QuipFactory, QuipWallet,
QuipPaymaster), and the EntryPoint isn't a contract this repo ships.

### Why the EntryPoint isn't shipped here

The ERC-4337 v0.7 EntryPoint is a STANDARDIZED SINGLETON deployed by
the eth-infinitism team at the canonical address
`0x0000000071727De22E5E9d8BAf0edAc6f37da032` on every EVM chain that
supports v0.7. Quip never deploys its own; the SDK just talks to the
canonical one for `getNonce`, `handleOps`, `depositTo`,
`getUserOpHash`, and the `UserOperationEvent` log. We don't need the
EntryPoint at all for these test-sdk scripts (we use the direct
`wallet.execute(payload)` path, no user ops), but the SDK exports
user-op-related methods alongside `executeWithPayload`, and TypeScript
needs the import to resolve for the file to compile.

### What was fixed

1. **`src/v1/abi/EntryPointV07.ts` (new)** — a one-line re-export:
   ```ts
   export { entryPoint07Abi as entryPointV07Abi } from "viem/account-abstraction";
   ```
   `viem` ships the canonical v0.7 ABI under `entryPoint07Abi`, sourced
   from eth-infinitism's release tag. Re-exporting under the SDK's
   existing `entryPointV07Abi` name leaves every consumer working
   unchanged with zero hand-typed JSON.

2. **`scripts/copy-abi.js` (patched)** — added an `EXTRA_BARREL_LINES`
   list so the regenerated `src/v1/abi/index.ts` barrel includes
   `export { entryPointV07Abi } from "./EntryPointV07.js";`. The
   hand-maintained `.ts` file itself is not overwritten — only its
   barrel line is woven into the generated index.

### Why this fix and not the alternatives considered

Three options were on the table:

- **A (chosen) — stub the ABI via viem re-export.** Smallest patch,
  fixes the actual underlying bug, no manual ABI maintenance ever,
  doesn't break tests or block future ERC-4337 / paymaster work.
- **B — bypass the build, run scripts against source via `tsx`.**
  Hides the bug from these scripts but leaves `npm run build` broken
  for everyone else, including CI and future releases.
- **C — comment out the EntryPoint imports + the seven downstream
  user-op methods on `QuipWalletClient`.** Mutates production SDK
  source for a test-infra problem, breaks the four `src/v1/tests/`
  ERC-4337 test files (which still run via Jest against
  `tsconfig.json`, not `tsconfig.build.json`), and has to be undone
  by hand whenever paymaster work resumes.

A is the only option that fixes the root cause without leaving traps
for the next developer.
