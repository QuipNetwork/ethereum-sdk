// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Ops: rotate the ShrincsPaymaster's STATEFUL verifier subkey to a different
// QUIP HD derivation index (owner-fiat `rotateStatefulKey`; the stateless half
// of the CURRENT bundle is carried forward, so the resulting live bundle is a
// graft: `deriveKeyPair({ statefulIndex: NEXT, statelessIndex: CURRENT_STATELESS })`).
//
// SIMULATES ONLY unless `--broadcast` is passed.
//
// Usage (after `npm run build`):
//   set -a; source .env; set +a
//   ROTATE_RPC_URL=$API_URL_BASE ROTATE_CHAIN_ID=8453 \
//   ROTATE_PAYMASTER=0x430c8c89492E3541e141148Dd7a7D6dD432e5890 \
//   ROTATE_CURRENT_STATEFUL_INDEX=0 ROTATE_CURRENT_STATELESS_INDEX=0 ROTATE_NEXT_INDEX=1 \
//     node scripts/rotate-shrincs-paymaster-key.mjs [--broadcast]
//
// Env: SHRINCS_OPERATOR_SECRET (0x + 32 bytes), PRIVATE_KEY (paymaster owner),
//      SHRINCS_VERIFIER_MAX_SIGNATURES (budget for the NEXT stateful key).

import { createPublicClient, createWalletClient, http, hexToBytes, isHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  ShrincsSigner,
  ShrincsCodec,
  shrincsPaymasterAbi,
} from "../dist/src/v1/shrincs/index.js";

function req(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}
function idx(name, dflt) {
  const v = process.env[name] ?? dflt;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0 || n >= 2 ** 31) throw new Error(`${name} must be an integer in [0, 2^31)`);
  return n;
}

const broadcast = process.argv.includes("--broadcast");
const secretHex = req("SHRINCS_OPERATOR_SECRET");
if (!isHex(secretHex) || hexToBytes(secretHex).length !== 32) throw new Error("SHRINCS_OPERATOR_SECRET must be 0x + 32 bytes");
const rpcUrl = req("ROTATE_RPC_URL");
const chainId = Number(req("ROTATE_CHAIN_ID"));
const paymasterAddress = req("ROTATE_PAYMASTER");
const currentStatefulIndex = idx("ROTATE_CURRENT_STATEFUL_INDEX", "0");
const currentStatelessIndex = idx("ROTATE_CURRENT_STATELESS_INDEX", String(currentStatefulIndex));
const nextIndex = idx("ROTATE_NEXT_INDEX");
const maxSignatures = Number(req("SHRINCS_VERIFIER_MAX_SIGNATURES"));
if (nextIndex === currentStatefulIndex) throw new Error("ROTATE_NEXT_INDEX must differ from the current stateful index");

const account = privateKeyToAccount(req("PRIVATE_KEY"));
const chain = { id: chainId, name: `chain-${chainId}`, nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [rpcUrl] } } };
const publicClient = createPublicClient({ chain, transport: http(rpcUrl) });
const walletClient = createWalletClient({ account, chain, transport: http(rpcUrl) });

const signer = await ShrincsSigner.create(hexToBytes(secretHex));

// Live state.
const [commitment, , keyVersion, liveMax, used] = await publicClient.readContract({
  address: paymasterAddress, abi: shrincsPaymasterAbi, functionName: "getShrincsVerifier",
});
const owner = await publicClient.readContract({ address: paymasterAddress, abi: shrincsPaymasterAbi, functionName: "owner" });

// Current bundle (graft-aware) must recompute to the live commitment.
const current = signer.deriveKeyPair({
  statefulIndex: currentStatefulIndex, statelessIndex: currentStatelessIndex, maxSignatures: Number(liveMax),
});
if (current.publicKeyCommitment.toLowerCase() !== commitment.toLowerCase()) {
  throw new Error(`current bundle (stateful ${currentStatefulIndex} / stateless ${currentStatelessIndex}) recomputes to ${current.publicKeyCommitment}, live is ${commitment}`);
}
const next = signer.recoverKeyPair(nextIndex, { maxSignatures });
const target = ShrincsCodec.buildStatefulRotationTarget({
  nextStatefulPublicKey: next.publicKey.statefulPublicKey,
  currentPkSeed: current.publicKey.pkSeed,
  currentHypertreeRoot: current.publicKey.hypertreeRoot,
});
const nextTree = ShrincsCodec.statefulTreeId(next.publicKey.statefulPublicKey);
if (nextTree === ShrincsCodec.statefulTreeId(current.publicKey.statefulPublicKey)) throw new Error("next stateful tree equals the installed one");

console.log(`paymaster        ${paymasterAddress} (chain ${chainId})`);
console.log(`owner            ${owner}  signer ${account.address}`);
console.log(`live commitment  ${commitment}  epoch ${keyVersion}  budget ${liveMax}  used ${used}`);
console.log(`current bundle   stateful idx ${currentStatefulIndex}, stateless idx ${currentStatelessIndex}`);
console.log(`next stateful    idx ${nextIndex}, tree ${nextTree}, budget ${maxSignatures}`);
console.log(`next commitment  ${target.publicKeyCommitment}`);
if (owner.toLowerCase() !== account.address.toLowerCase()) throw new Error("PRIVATE_KEY is not the paymaster owner");

const args = [
  ShrincsCodec.publicKeyToAbi(current.publicKey),
  { statefulPublicKey: target.statefulPublicKey, publicKeyCommitment: target.publicKeyCommitment },
];
const sim = await publicClient.simulateContract({
  address: paymasterAddress, abi: shrincsPaymasterAbi, functionName: "rotateStatefulKey", args, account: account.address,
});
console.log(`simulation OK    gas ${sim.request.gas ?? "(estimated by client)"}`);

if (!broadcast) {
  console.log("\nDRY RUN — pass --broadcast to send.");
  process.exit(0);
}

// Sign locally with the simulated request (the SDK client hands viem a bare
// address as `account`, which routes to eth_sendTransaction on the node).
const hash = await walletClient.writeContract({ ...sim.request, account });
console.log(`sent     tx ${hash}`);
const receipt = await publicClient.waitForTransactionReceipt({ hash });
console.log(`rotated  tx ${receipt.transactionHash}  block ${receipt.blockNumber}  status ${receipt.status}`);
const [c2, , v2] = await publicClient.readContract({ address: paymasterAddress, abi: shrincsPaymasterAbi, functionName: "getShrincsVerifier" });
console.log(`live now         commitment ${c2}  epoch ${v2}`);
console.log(`\nSponsor client config for this chain: deriveKeyPair({ statefulIndex: ${nextIndex}, statelessIndex: ${currentStatelessIndex}, maxSignatures: ${maxSignatures} })`);
