# Test vectors — ShrincsPaymaster (status: GENERATED ✅)

`test/test_vectors/shrincs_paymaster_sphincs_256s_keccak.json` has been generated under the
single-global-verifier + used-leaf-bitmap scheme. The full suite (including the sponsorship-success
and out-of-order paths) runs end-to-end against these vectors — no skipped tests remain.

The Rust generator is `hashsigs-rs` `tests/generate_shrincs_paymaster_vectors.rs`.

Regenerate:

```
cd ../hashsigs-rs && cargo test --test generate_shrincs_paymaster_vectors -- --ignored --nocapture
cp tests/test_vectors/shrincs_paymaster_sphincs_256s_keccak.json ../quip-solidity/test/test_vectors/
```

## Fixed signing constants (must match `ShrincsPaymasterTest` and the generator)

- paymaster address: `0x5B38Da6a701c568545dCfcB03FcB875f56beddC4`
- chainId: `31337`; verifier `maxSignatures`: `8`; `keyVersion`: `0`
- domain separator: `EfficientHashLib.hash("quip-shrincs-paymaster-v1", chainId, paymaster)`
- actionType: `keccak256("quip.shrincs.action.paymasterApprove")`
- **stateful `ActionContext.nonce` is always `0`** (anti-replay = used-leaf bitmap); the leaf index
  is carried by `signature.authPath.length`.

## What the vectors bind

Each sponsorship signs the paymaster's `_userOpBindingHash` =
`hash(sender, nonce, keccak(initCode), keccak(callData), accountGasLimits, preVerificationGas,
gasFees, keccak(paymasterAndData[:64]))` over a FIXED userOp (the `userOp` object in the JSON;
`nonce` varies per case). The `paymasterAndData[:64]` prefix is `paymaster(20) ‖
verificationGasLimit(16) ‖ postOpGasLimit(16) ‖ validUntil(6) ‖ validAfter(6)`; the signature blob
at `[64:]` is excluded from the hash, so the test embeds the signature after signing the prefix.

`cases.sponsor[0..2]` carry leaves `1..3` (nonce = leaf). The Solidity tests use `[0]` for the
success path and `[2]` then `[1]` (leaf 3 then 2) for out-of-order acceptance.

`cases.sponsorWithWindow` carries leaf `4` signed over a NON-ZERO validity window
(`validUntil = 0xAAAAAA`, `validAfter = 0x555555`, baked into the signed `paymasterAndData[:64]`
prefix). `test_validate_succeeds_packsValidityWindow` asserts `validatePaymasterUserOp` packs
`validationData == (validUntil << 160) | (validAfter << 208)` with the two bounds in the correct,
non-transposed slots — the only path exercising the window packing with non-zero values.

No `removeShrincsVerifier` / `NoVerifierRegistered` cases exist — the paymaster always has a verifier
(installed at `initialize`, rotated via `setShrincsVerifier`).
