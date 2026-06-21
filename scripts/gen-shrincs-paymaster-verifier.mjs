// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Generates the ShrincsPaymaster verifier-key commitment to seal into the
// paymaster's `initialize(...)` at deploy time. The SAME (secret, vaultId,
// maxSignatures) MUST be held by the paymaster sponsorship backend afterward —
// it is how `ShrincsPaymasterClient.sponsorUserOp` re-derives the signing key.
// Back them up securely; losing them bricks sponsorship for this verifier epoch.
//
// Usage (after `npm run build`):
//   SHRINCS_OPERATOR_SECRET=0x<32 bytes> \
//   SHRINCS_VERIFIER_VAULT_ID=0x<32 bytes> \
//   SHRINCS_VERIFIER_MAX_SIGNATURES=1024 \
//     node scripts/gen-shrincs-paymaster-verifier.mjs

import { hexToBytes, isHex } from "viem";
import { ShrincsSigner } from "../dist/src/v1/shrincs/index.js";

function req(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

const secretHex = req("SHRINCS_OPERATOR_SECRET");
const vaultId = req("SHRINCS_VERIFIER_VAULT_ID");
const maxSignatures = Number(req("SHRINCS_VERIFIER_MAX_SIGNATURES"));

if (!isHex(secretHex) || hexToBytes(secretHex).length !== 32)
  throw new Error("SHRINCS_OPERATOR_SECRET must be 0x + 32 bytes");
if (!isHex(vaultId) || hexToBytes(vaultId).length !== 32)
  throw new Error("SHRINCS_VERIFIER_VAULT_ID must be 0x + 32 bytes");
if (!Number.isInteger(maxSignatures) || maxSignatures <= 0)
  throw new Error("SHRINCS_VERIFIER_MAX_SIGNATURES must be a positive integer");

const signer = await ShrincsSigner.create(hexToBytes(secretHex));
const kp = signer.recoverKeyPair(vaultId, { maxSignatures });

console.log("\n=== ShrincsPaymaster verifier (set these in .env) ===");
console.log(`SHRINCS_VERIFIER_COMMITMENT=${kp.publicKeyCommitment}`);
console.log(`SHRINCS_VERIFIER_MAX_SIGNATURES=${maxSignatures}`);
console.log(`SHRINCS_VERIFIER_PARAM_SET_ID=0`);
console.log("\nKeep SECRET + back up (paymaster backend reuses these to sign):");
console.log(`  SHRINCS_OPERATOR_SECRET  = ${secretHex.slice(0, 6)}…(hidden)`);
console.log(`  SHRINCS_VERIFIER_VAULT_ID= ${vaultId}`);
