// Smoke check: runs inside the scratch project after the tarball is
// installed. Verifies the SDK's public surface is reachable and a
// purely-local code path executes correctly. No network access.
//
// What this catches that the in-repo tests don't:
//   - Missing `dist/` files (the `files` glob in package.json drifts)
//   - Broken subpath exports (`./v1/errors`, `./deprecated/v0`, etc.)
//   - ESM/CJS interop regressions
//   - Type-import-only paths that vanish after tree-shaking
//   - Re-exports referencing symbols that didn't make it into dist
//   - Re-introduction of a root `.` export (the symmetric layout
//     intentionally forbids one; a future change adding one back
//     should fail this script)
//   - Regression of the WOTS+ sunset split: WOTS+ classes must live at
//     `./deprecated/v0`, NOT in the live `./v1` barrel; the retired WOTS+
//     subpaths must fail loudly.
import assert from "node:assert/strict";

console.log("  - live v1 barrel (shared surface only)...");
const live = await import("@quip.network/ethereum-sdk/v1");
assert(Array.isArray(live.walletFactoryAbi), "walletFactoryAbi missing from v1 barrel");
assert(typeof live.CANONICAL_ENTRYPOINT_V07 === "string", "CANONICAL_ENTRYPOINT_V07 missing");
assert(typeof live.computeUserOpHash === "function", "computeUserOpHash missing (userOpCodec)");
assert(typeof live.QuipError === "function", "QuipError missing from v1 barrel");
assert(live.QuipSigner === undefined, "QuipSigner leaked into the live v1 barrel — WOTS+ surface must stay in ./deprecated/v0");
assert(live.WotsCodec === undefined, "WotsCodec leaked into the live v1 barrel");
assert(live.deployerAbi === undefined, "deployerAbi leaked into the live v1 barrel — the Deployer is sunset WOTS+-era infra (live deploys go straight through CreateX)");

console.log("  - live v1 subpath exports...");
const liveErrors = await import("@quip.network/ethereum-sdk/v1/errors");
assert(typeof liveErrors.InvalidSignatureError === "function", "InvalidSignatureError via subpath");
const userOpCodec = await import("@quip.network/ethereum-sdk/v1/userOpCodec");
assert(typeof userOpCodec.packAccountGasLimits === "function", "packAccountGasLimits via userOpCodec subpath");

console.log("  - deprecated v0 barrel (legacy WOTS+ surface)...");
const v0 = await import("@quip.network/ethereum-sdk/deprecated/v0");
assert(typeof v0.QuipSigner === "function", "QuipSigner missing from v0 barrel");
assert(typeof v0.QuipWalletClient === "function", "QuipWalletClient missing from v0 barrel");
assert(typeof v0.QuipClient === "function", "QuipClient missing from v0 barrel");
assert(typeof v0.QuipWallet__factory === "function", "QuipWallet__factory missing");
assert(typeof v0.QuipFactory__factory === "function", "QuipFactory__factory missing (v0 contract keeps its historical name)");
assert(typeof v0.QuipWallet__factory.connect === "function", "QuipWallet__factory.connect missing");
assert(v0.SUPPORTED_NETWORKS?.MAINNET === "mainnet", "v0 SUPPORTED_NETWORKS.MAINNET");
assert(v0.CHAIN_IDS?.ETHEREUM_MAINNET === 1, "v0 CHAIN_IDS.ETHEREUM_MAINNET");

console.log("  - root barrel rejected...");
await assert.rejects(
  () => import("@quip.network/ethereum-sdk"),
  /ERR_PACKAGE_PATH_NOT_EXPORTED/,
  "root import should fail loudly after symmetric split"
);

console.log("  - retired WOTS+ subpaths rejected...");
// The pre-split live paths (moved to ./deprecated/*) and the removed
// deprecated/v1 ERC-4337 WOTS+ family (superseded by SHRINCS; legacy WOTS+
// now serves only through ./deprecated/v0) must all fail loudly.
const retiredPaths = [
  "v1/signer",
  "v1/walletClient",
  "v1/wotsCodec",
  "v1/events",
  "v1/userOp",
  "v0",
  "deprecated/v1",
  "deprecated/v1/signer",
  "deprecated/v1/walletClient",
  "deprecated/v1/factoryClient",
  "deprecated/v1/paymaster",
  "deprecated/v1/errors",
  "deprecated/v1/events",
  "deprecated/v1/userOp",
  "deprecated/v1/wotsCodec",
];
for (const retired of retiredPaths) {
  await assert.rejects(
    () => import(`@quip.network/ethereum-sdk/${retired}`),
    /ERR_PACKAGE_PATH_NOT_EXPORTED/,
    `retired subpath ./${retired} should no longer resolve`
  );
}

console.log("  - v0 signer round-trip (no network)...");
const v0Signer = new v0.QuipSigner(new Uint8Array(32).fill(0x01));
const v0VaultId = new Uint8Array(32).fill(0x02);
const keypair = v0Signer.generateKeyPair(v0VaultId);
assert(keypair.publicKey.publicSeed instanceof Uint8Array, "v0 keypair publicSeed shape");
const v0Sig = v0Signer.sign(new Uint8Array(32).fill(0x77), v0VaultId, keypair.publicKey.publicSeed);
assert(Array.isArray(v0Sig) && v0Sig.length === 67, `v0 WOTS+ sig should have 67 elements, got ${v0Sig.length}`);

console.log("OK");
