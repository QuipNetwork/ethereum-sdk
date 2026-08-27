// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Generates the ShrincsPaymaster verifier public-key bundle to seal into the
// paymaster's `initialize(...)` at deploy time (the contract derives the
// commitment and the stateful leaf budget from the bundle — they are never
// trusted parameters). The SAME (secret, derivationIndex, maxSignatures) MUST
// be held by the paymaster sponsorship backend afterward — pass that integer
// as `ShrincsPaymasterClient({ derivationIndex })` so `sponsorUserOp`
// re-derives the signing key. Back them up securely; losing them bricks
// sponsorship for this verifier epoch.
//
// Usage (after `npm run build`):
//   SHRINCS_OPERATOR_SECRET=0x<32 bytes> \
//   SHRINCS_VERIFIER_DERIVATION_INDEX=0 \
//   SHRINCS_VERIFIER_MAX_SIGNATURES=1024 \
//     node scripts/gen-shrincs-paymaster-verifier.mjs
//
// SHRINCS_VERIFIER_DERIVATION_INDEX is optional and defaults to 0. It must
// parse as a decimal integer in [0, 2^31).

import { hexToBytes, isHex } from "viem";
import { ShrincsSigner, ShrincsCodec } from "../dist/src/v1/shrincs/index.js";

function req(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

function parseDerivationIndex(raw) {
  const n = Number(raw);
  if (!/^[0-9]+$/.test(raw) || !Number.isInteger(n) || n < 0 || n >= 2 ** 31) {
    throw new Error(
      "SHRINCS_VERIFIER_DERIVATION_INDEX must be an integer in [0, 2^31)"
    );
  }
  return n;
}

const secretHex = req("SHRINCS_OPERATOR_SECRET");
const derivationIndex = parseDerivationIndex(
  process.env.SHRINCS_VERIFIER_DERIVATION_INDEX ?? "0"
);
const maxSignatures = Number(req("SHRINCS_VERIFIER_MAX_SIGNATURES"));

if (!isHex(secretHex) || hexToBytes(secretHex).length !== 32)
  throw new Error("SHRINCS_OPERATOR_SECRET must be 0x + 32 bytes");
if (!Number.isInteger(maxSignatures) || maxSignatures <= 0)
  throw new Error("SHRINCS_VERIFIER_MAX_SIGNATURES must be a positive integer");

const signer = await ShrincsSigner.create(hexToBytes(secretHex));
const kp = signer.recoverKeyPair(derivationIndex, { maxSignatures });

console.log("\n=== ShrincsPaymaster verifier (set this in .env) ===");
console.log(`SHRINCS_VERIFIER_PUBLIC_KEY=${ShrincsCodec.encodePublicKeyBundle(kp.publicKey)}`);
console.log("# SHRINCS_VERIFIER_HASH_SUITE unset -> defaults to the keccak suite");
console.log("\nDerived on-chain from the bundle at initialize (informational):");
console.log(`  commitment    = ${kp.publicKeyCommitment}`);
console.log(`  maxSignatures = ${maxSignatures}`);
console.log("\nKeep SECRET + back up (paymaster backend reuses these to sign):");
console.log(`  SHRINCS_OPERATOR_SECRET  = ${secretHex.slice(0, 6)}…(hidden)`);
console.log(`  SHRINCS_VERIFIER_DERIVATION_INDEX= ${derivationIndex}`);
