// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Generates the ShrincsPaymaster verifier public-key bundle to seal into the
// paymaster's `initialize(...)` at deploy time (the contract derives the
// commitment and the stateful leaf budget from the bundle — they are never
// trusted parameters). The SAME (secret, chainId, epoch, maxSignatures) MUST
// be held by the paymaster sponsorship backend afterward — it re-derives the
// signing key with `ShrincsSigner.create(secret, { network: chainId })` and
// `ShrincsPaymasterClient({ derivationIndex: epoch })`. Back them up securely;
// losing them bricks sponsorship for this verifier epoch.
//
// ONE KEY PER CHAIN. A stateful SHRINCS key is a one-time-signature tree and
// the used-leaf bitmap that guards it lives in ONE paymaster contract. The
// paymaster's signing domain binds `block.chainid`, so the same key installed
// on two chains signs a DIFFERENT message at the same leaf on each — an OTS
// reuse that lowers the forgery cost of that leaf. Keys are therefore derived
// under the QUIP HD path
//
//   m/20814'/algorithm'/<chainId>'/account'/<epoch>'
//
// i.e. the path's `network` level is the target chain id and the derivation
// index is the per-chain rotation epoch (0 for the first key). Every
// (chainId, epoch) pair yields a distinct tree, and a bundle produced here
// must be installed on exactly that chain, ever.
//
// Usage (after `npm run build`):
//   SHRINCS_OPERATOR_SECRET=0x<32 bytes> \
//   SHRINCS_VERIFIER_CHAIN_ID=8453 \
//   SHRINCS_VERIFIER_MAX_SIGNATURES=1024 \
//     node scripts/gen-shrincs-paymaster-verifier.mjs
//
// Env:
//   SHRINCS_VERIFIER_CHAIN_ID       required; the ONE chain this bundle is for.
//   SHRINCS_VERIFIER_EPOCH          optional; per-chain rotation epoch, default 0.
//   SHRINCS_VERIFIER_MAX_SIGNATURES required; stateful leaf budget.
//   SHRINCS_VERIFIER_HD_NETWORK     optional; overrides the HD `network` level.
//                                   ONLY to reproduce a key recorded in
//                                   DEPLOYMENTS.md before the per-chain
//                                   convention (those used the default level).
// All integers must be decimal in [0, 2^31).

import { hexToBytes, isHex } from "viem";
import {
  ShrincsSigner,
  ShrincsCodec,
  quipHdPath,
} from "../dist/src/v1/shrincs/index.js";

function req(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

function parseIndex(name, raw) {
  const n = Number(raw);
  if (!/^[0-9]+$/.test(raw) || !Number.isInteger(n) || n < 0 || n >= 2 ** 31) {
    throw new Error(`${name} must be an integer in [0, 2^31)`);
  }
  return n;
}

const secretHex = req("SHRINCS_OPERATOR_SECRET");
const chainId = parseIndex("SHRINCS_VERIFIER_CHAIN_ID", req("SHRINCS_VERIFIER_CHAIN_ID"));
const epoch = parseIndex("SHRINCS_VERIFIER_EPOCH", process.env.SHRINCS_VERIFIER_EPOCH ?? "0");
const hdNetworkRaw = process.env.SHRINCS_VERIFIER_HD_NETWORK;
const hdNetwork =
  hdNetworkRaw === undefined
    ? chainId
    : parseIndex("SHRINCS_VERIFIER_HD_NETWORK", hdNetworkRaw);
const maxSignatures = Number(req("SHRINCS_VERIFIER_MAX_SIGNATURES"));

if (!isHex(secretHex) || hexToBytes(secretHex).length !== 32)
  throw new Error("SHRINCS_OPERATOR_SECRET must be 0x + 32 bytes");
if (!Number.isInteger(maxSignatures) || maxSignatures <= 0)
  throw new Error("SHRINCS_VERIFIER_MAX_SIGNATURES must be a positive integer");

const pathOptions = { network: hdNetwork };
const signer = await ShrincsSigner.create(hexToBytes(secretHex), pathOptions);
const kp = signer.recoverKeyPair(epoch, { maxSignatures });

if (hdNetwork !== chainId) {
  console.warn(
    `\nWARNING: HD network level ${hdNetwork} differs from chain id ${chainId}` +
      ` (legacy derivation). This bundle must still be installed on chain ${chainId}` +
      ` ONLY — never reuse a sponsorship key across chains (one-time leaves, per-contract bitmap).`
  );
}

console.log(`\n=== ShrincsPaymaster verifier for chain ${chainId} (set this in .env) ===`);
console.log(`SHRINCS_VERIFIER_PUBLIC_KEY=${ShrincsCodec.encodePublicKeyBundle(kp.publicKey)}`);
console.log("# SHRINCS_VERIFIER_HASH_SUITE unset -> defaults to the keccak suite");
console.log("\nDerived on-chain from the bundle at initialize (informational):");
console.log(`  commitment    = ${kp.publicKeyCommitment}`);
console.log(`  maxSignatures = ${maxSignatures}`);
console.log(`  HD path       = ${quipHdPath(epoch, pathOptions)}`);
console.log("\nKeep SECRET + back up (paymaster backend reuses these to sign):");
console.log(`  SHRINCS_OPERATOR_SECRET      = ${secretHex.slice(0, 6)}…(hidden)`);
console.log(`  SHRINCS_VERIFIER_CHAIN_ID    = ${chainId}`);
console.log(`  SHRINCS_VERIFIER_EPOCH       = ${epoch}`);
if (hdNetwork !== chainId) console.log(`  SHRINCS_VERIFIER_HD_NETWORK  = ${hdNetwork}`);
console.log("\nSponsor backend config (install on chain " + chainId + " and no other):");
console.log(`  const signer = await ShrincsSigner.create(secret, { network: ${hdNetwork} });`);
console.log(`  new ShrincsPaymasterClient({ ...params, signer, derivationIndex: ${epoch} });`);
