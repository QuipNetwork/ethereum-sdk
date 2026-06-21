# Test vectors — ShrincsWallet (status: REGENERATED ✅)

`test/test_vectors/shrincs_wallet_sphincs_256s_keccak.json` has been **regenerated** under the
no-nonce stateful scheme (used-leaf bitmap anti-replay; see `project_shrincs_wallet_antireplay`).
The Rust generator is `hashsigs-rs` (branch `shrincs-main`)
`tests/generate_shrincs_wallet_vectors.rs`. `_parseStatelessSignature` in
`ShrincsWallet.t.sol` now decodes the full `fors` + `hypertree` layers.

Regenerate:

```
cd ../hashsigs-rs && cargo test --test generate_shrincs_wallet_vectors -- --ignored --nocapture
cp tests/test_vectors/shrincs_wallet_sphincs_256s_keccak.json ../quip-solidity/test/test_vectors/
```

## Fixed signing constants (must match `ShrincsWalletTest`)

- wallet address: `0x5B38Da6a701c568545dCfcB03FcB875f56beddC4`
- chainId: `31337`
- `maxSignatures` (main key): `8`
- domain separator: `EfficientHashLib.hash("quip-shrincs-wallet-v1", chainId, wallet)` (in vectors
  as `.domainSeparator`).
- **stateful `ActionContext.nonce` is always `0`** (anti-replay = used-leaf bitmap, not a wrapper
  nonce); leaf index is carried by `signature.authPath.length`.
- Sphincs256sKeccakQ20 stateless signatures reveal **21 FORS-C entries** + **8 hypertree layers**.

## Cases (`.cases.*`) and the deterministic targets they bind

| Case | actionType | payloadHash / context | bound target |
|---|---|---|---|
| `erc4337[0..2]` (leaves 1,2,3) | `quip.shrincs.action.erc4337Execute` | `hash(userOpHash, fee)` | — |
| `execute` | `quip.shrincs.action.execute` | `hash(target, value, keccak(data), fee)` | `0xBEEF`, 0, empty, fee 0 |
| `executeEth` | `quip.shrincs.action.execute` | `hash(target, value, keccak(data), fee)` | `0xBEEF`, 1 ether, empty |
| `executeCall` | `quip.shrincs.action.execute` | `hash(target, value, keccak(data), fee)` | `0xCA11`, 0, `0x1234` (test etches a callee) |
| `withdraw` | `quip.shrincs.action.withdrawDeposit` | `hash(to, amount)` | `0xD00D`, 0 |
| `transferOwnership` | `quip.shrincs.action.transferOwnership` (stateful) + stateless rotation | `hash(newOwner, nextCommitment)` | `newOwner = makeAddr("newOwner")` = `0x7240b687730BE024bcfD084621f794C2e4F8408f`; `nextKey` = `.cases.rotateFullKey.nextKey` |
| `setErc1271Key` | `quip.shrincs.action.setErc1271Key` | `hash(newCommitment, newParameterSetId)` | — |
| `rotateKey` | `quip.shrincs.action.rotateKey` | `hash(nextCommitment, nextParameterSetId)` | `nextStatefulKey` |
| `upgrade` | `quip.shrincs.action.upgrade` | `hash(newImplementation, shouldMigrate?1:0, keccak(migratorPayload))` | impl `0xBEEF`, no migrate |
| `rotateFullKey` (= `recoverWallet`) | stateless `RotationContext{nonce:0, keyVersion:0}` | rotation to `nextKey` | — |
| `erc1271` | `quip.shrincs.action.erc1271` | `payloadHash = hash`, nonce 0 | dedicated ERC-1271 key |

`transferOwnership` carries BOTH a `signature` (stateful owner-binding over `(newOwner,
nextCommitment)`) and a `recoverySignature` (stateless full rotation to the same `nextKey` the
`rotateFullKey` case uses). The ERC-1271 owner ECDSA half is produced on-chain from `OWNER_PK`
over `quipSignedHashEcdsaTarget(hash)` and needs no vector.

## Status

No skipped tests remain. The `execute` ETH-transfer / contract-call paths are driven by the
`executeEth` / `executeCall` vectors, and the `upgradeToAndCall` success + `GuardedSlotTampered`
paths run end-to-end by etching a vetted mock implementation at the signed `0xBEEF` (a plain
`proxiableUUID` without `notDelegated` so it survives `vm.etch`).
