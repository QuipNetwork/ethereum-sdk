# TODO

## Keep the deploy operator key out of `argv`

### Problem

Every per-chain deploy target passes the key on the command line:

```make
deploy-factory-base-sepolia:
	forge script script/01_DeployFactory.s.sol \
	  --rpc-url base_sepolia \
	  --private-key $(PRIVATE_KEY) \
	  --broadcast --verify
```

Make expands `$(PRIVATE_KEY)` before `exec`, so during a live broadcast the raw
key sits in the process's `argv` — readable by any local process via `ps aux`.
It also renders in `make -n` output and lands in shell history whenever the raw
`forge script` form is run by hand.

The exposed key is `DEPLOY_OPERATOR` / `DeployConstants.CANONICAL_OPERATOR`
(`0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26`), which is not an ordinary hot
wallet:

- it owns the live WalletFactory proxy and the ShrincsPaymaster proxy on Base
  mainnet, so it can vet implementations, move fees, and upgrade either contract;
- every canonical address is a function of it (sender-guarded CreateX salts), so
  it is the *only* key that can ever materialize the canonical set on a new chain.

Separately, `.env` — which holds the same key — is mode `644`, i.e.
world-readable. It is correctly gitignored and untracked.

### Fix (immediate, no behaviour change)

Drop `--private-key $(PRIVATE_KEY)` from the deploy targets. The flag is
redundant: all nine deploy scripts read the key themselves with
`vm.envUint("PRIVATE_KEY")` and every broadcast goes through
`vm.startBroadcast(privateKey)` with that value (`script/DeployHelpers.sol:50`,
`script/CreateXHelpers.sol:152`). Nothing consumes the CLI flag.

Verified: `forge script script/DeployShrincsWallet.s.sol --rpc-url base_sepolia`
with no `--private-key` resolves the operator and simulates correctly.

Also `chmod 600 .env`.

This narrows exposure to the plaintext `.env` on disk, which forge still reads.

### Longer term: encrypted keystore or hardware wallet

The proper end state for a key with mainnet upgrade authority:

```sh
cast wallet import quip-operator --interactive   # once
forge script ... --account quip-operator --sender $DEPLOY_OPERATOR
```

This is a refactor, not a flag swap. The scripts currently hold the raw key as a
`uint256` and pass it explicitly, so all of the following change together:

- `vm.startBroadcast(pk)` → `vm.startBroadcast()` in `DeployHelpers._vetIfNeeded`
  and `CreateXHelpers._createXDeploy`, dropping the `pk` parameter that is
  threaded through `_deployFactoryViaCreateX`, `_deployShrincsImplAndVet`, and
  `_deployShrincsPaymaster`;
- the `require(vm.addr(privateKey) == operator, ...)` pre-flight in
  `01_DeployFactory`, `02_DeployShrincs`, and `DeployShrincsWallet` has no key to
  derive from and must be rewritten against the broadcast sender;
- the sunset WOTS+ scripts under `script/deprecated/` use the same pattern.

### Open design questions

- Keystore or hardware wallet? A Ledger removes the plaintext key entirely but
  makes unattended/CI deploys impossible — the operator key is currently the
  single signer for every canonical deploy on every chain, forever.
- With `--account`, how should the canonical-operator pre-flight assert identity
  before any broadcast? `--sender` is caller-supplied, so the check has to fail
  closed if it disagrees with `DeployConstants.CANONICAL_OPERATOR`.
- Should the deprecated WOTS+ scripts be migrated too, or left on the env-var
  path since they are sunset and their salts are already consumed?

## Remove the deployed-caller shape sniff in `ShrincsWallet.verifyUpgrade`

`verifyUpgrade(address,bytes)` accepts two canonical input shapes, told apart by
the first calldata word:

- `0xc0` — the ENTIRE 6-field upgrade-auth blob. Only the DEPLOYED SHRINCS
  implementation (`V1.0.1-beta.2`, `0x680840c831c6D147404a0e00edA08a5360564FBC`)
  produces this: its frozen bytecode forwards its whole blob to the probe
  instead of cutting out field[5] first. The branch decodes the blob and
  extracts the opaque `probePayload` from field[5].
- `0x60` — the bare 3-field probe vector `(bundle, statefulSig, statelessSig)`.
  This is the seam convention: the SENDER unwraps, the receiver only ever sees
  its own family's vector.

The `word[0] == 0xc0` branch exists solely for upgrades arriving FROM the
deployed implementation. Once nothing lives on that codehash (all live wallets
upgraded off it, or it is deliberately stranded), a future implementation should
delete the branch and accept only the bare vector. Consequence of removal:
wallets still on the deployed implementation can no longer upgrade directly to
that future implementation — they must hop through an intermediate one that
still carries the branch. The blob format itself never changes.
