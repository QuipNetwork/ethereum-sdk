// Copyright (C) 2025 quip.network
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Ops: rotate the ShrincsPaymaster's STATEFUL verifier subkey (owner-fiat
// `rotateStatefulKey`; the stateless half of the CURRENT bundle is carried
// forward, so the resulting live bundle is a graft).
//
// ONE KEY PER CHAIN. Sponsorship keys live under the QUIP HD path
//   m/20814'/algorithm'/<chainId>'/account'/<epoch>'
// (see gen-shrincs-paymaster-verifier.mjs): the `network` level is the chain
// id and the index is the per-chain rotation epoch. The NEXT stateful key is
// always derived that way for ROTATE_CHAIN_ID. The CURRENT bundle is
// recomputed from its recorded coordinates, which for deployments made before
// this convention sit under the default network level (legacy, 20049).
//
// SIMULATES ONLY unless `--broadcast` is passed.
//
// Usage (after `npm run build`):
//   set -a; source .env; set +a
//   ROTATE_RPC_URL=$API_URL_BASE ROTATE_CHAIN_ID=8453 \
//   ROTATE_PAYMASTER=0x430c8c89492E3541e141148Dd7a7D6dD432e5890 \
//   ROTATE_CURRENT_STATEFUL_INDEX=1 ROTATE_CURRENT_STATELESS_INDEX=0 \
//   ROTATE_CURRENT_HD_NETWORK=20049 ROTATE_NEXT_EPOCH=0 \
//     node scripts/rotate-shrincs-paymaster-key.mjs [--broadcast]
//
// Env: SHRINCS_OPERATOR_SECRET (0x + 32 bytes), PRIVATE_KEY (paymaster owner),
//      SHRINCS_VERIFIER_MAX_SIGNATURES (budget for the NEXT stateful key),
//      ROTATE_CURRENT_STATELESS_INDEX (defaults to the current stateful index),
//      ROTATE_CURRENT_HD_NETWORK (HD network level of the CURRENT bundle;
//        default: the chain id, i.e. an already chain-scoped key; pass the
//        legacy default level 20049 for pre-convention deployments),
//      ROTATE_NEXT_EPOCH (per-chain epoch of the NEXT stateful key; must be
//        greater than ROTATE_CURRENT_STATEFUL_INDEX when the current bundle
//        is already chain-scoped, since pre-registry trees on upgraded proxies
//        are not covered on-chain; ROTATE_ALLOW_NONMONOTONIC=1 relaxes that to
//        "must differ" for recovery).

import {
  createPublicClient,
  createWalletClient,
  http,
  hexToBytes,
  isHex,
  isAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  ShrincsSigner,
  ShrincsCodec,
  shrincsPaymasterAbi,
  quipHdPath,
} from "../dist/src/v1/shrincs/index.js";

function req(name) {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}
function idx(name, dflt) {
  const v = dflt === undefined ? req(name) : (process.env[name] ?? dflt);
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0 || n >= 2 ** 31) {
    throw new Error(`${name} must be an integer in [0, 2^31)`);
  }
  return n;
}

const broadcast = process.argv.includes("--broadcast");
const secretHex = req("SHRINCS_OPERATOR_SECRET");
if (!isHex(secretHex) || hexToBytes(secretHex).length !== 32) {
  throw new Error("SHRINCS_OPERATOR_SECRET must be 0x + 32 bytes");
}
const rpcUrl = req("ROTATE_RPC_URL");
const chainId = Number(req("ROTATE_CHAIN_ID"));
if (!Number.isInteger(chainId) || chainId <= 0) {
  throw new Error("ROTATE_CHAIN_ID must be a positive integer");
}
const paymasterAddress = req("ROTATE_PAYMASTER");
if (!isAddress(paymasterAddress)) {
  throw new Error("ROTATE_PAYMASTER must be a valid address");
}
const currentStatefulIndex = idx("ROTATE_CURRENT_STATEFUL_INDEX", "0");
const currentStatelessIndex = idx("ROTATE_CURRENT_STATELESS_INDEX", String(currentStatefulIndex));
const currentHdNetwork = idx("ROTATE_CURRENT_HD_NETWORK", String(chainId));
const nextEpoch = idx("ROTATE_NEXT_EPOCH");
const maxSignatures = Number(req("SHRINCS_VERIFIER_MAX_SIGNATURES"));
if (
  !Number.isInteger(maxSignatures) ||
  maxSignatures <= 0 ||
  maxSignatures > 2 ** 32 - 1
) {
  throw new Error(
    "SHRINCS_VERIFIER_MAX_SIGNATURES must be an integer in [1, 2^32)"
  );
}
const currentPath = { network: currentHdNetwork };
const nextPath = { network: chainId };
// Pre-registry trees on upgraded proxies are not covered on-chain, so a
// rotation back to an older epoch under the same HD network would succeed.
// Monotonic epochs make cycling back impossible from this script. Set
// ROTATE_ALLOW_NONMONOTONIC=1 to restore the plain !== check for recovery.
// A legacy current bundle (different network level) has no ordering relation
// to chain-scoped epochs, so any epoch is accepted for that first migration.
if (currentHdNetwork === chainId) {
  if (process.env.ROTATE_ALLOW_NONMONOTONIC === "1") {
    if (nextEpoch === currentStatefulIndex) {
      throw new Error(
        "ROTATE_NEXT_EPOCH must differ from the current stateful epoch on this chain"
      );
    }
  } else if (nextEpoch <= currentStatefulIndex) {
    throw new Error(
      "ROTATE_NEXT_EPOCH must be greater than the current stateful epoch on this chain"
    );
  }
}

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
  statefulPath: currentPath, statelessPath: currentPath,
});
if (current.publicKeyCommitment.toLowerCase() !== commitment.toLowerCase()) {
  throw new Error(`current bundle (stateful ${currentStatefulIndex} / stateless ${currentStatelessIndex} @ network ${currentHdNetwork}) recomputes to ${current.publicKeyCommitment}, live is ${commitment}`);
}
// NEXT stateful key: chain-scoped by construction.
const next = signer.keygenFromSeedHex(signer.deriveSeedHex(nextEpoch, nextPath), { maxSignatures });
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
console.log(`current bundle   stateful idx ${currentStatefulIndex}, stateless idx ${currentStatelessIndex}, HD network ${currentHdNetwork}`);
console.log(`next stateful    epoch ${nextEpoch} @ HD network ${chainId} (${quipHdPath(nextEpoch, nextPath)}), tree ${nextTree}, budget ${maxSignatures}`);
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
if (receipt.status !== "success") {
  console.error(
    `rotation tx ${receipt.transactionHash} reverted ` +
      `(status ${receipt.status})`
  );
  process.exit(1);
}
console.log(
  `rotated  tx ${receipt.transactionHash}  block ${receipt.blockNumber}  ` +
    `status ${receipt.status}`
);
const [c2, , v2] = await publicClient.readContract({
  address: paymasterAddress,
  abi: shrincsPaymasterAbi,
  functionName: "getShrincsVerifier",
});
if (c2.toLowerCase() !== target.publicKeyCommitment.toLowerCase()) {
  console.error(
    `live commitment ${c2} does not match expected ` +
      `${target.publicKeyCommitment}`
  );
  process.exit(1);
}
console.log(`live now         commitment ${c2}  epoch ${v2}`);
console.log(
  `\nSponsor client config for chain ${chainId} (pass as \`keypair\`):\n` +
  `  signer.deriveKeyPair({ statefulIndex: ${nextEpoch}, statefulPath: { network: ${chainId} },` +
  ` statelessIndex: ${currentStatelessIndex}, statelessPath: { network: ${currentHdNetwork} }, maxSignatures: ${maxSignatures} })`
);
