// Smoke check: runs inside the scratch project after the tarball is
// installed. Verifies the SDK's public surface is reachable and a
// purely-local code path executes correctly. No network access.
//
// What this catches that the in-repo tests don't:
//   - Missing `dist/` files (the `files` glob in package.json drifts)
//   - Broken subpath exports (`./v1/errors`, `./deprecated/v1`, etc.)
//   - ESM/CJS interop regressions
//   - Type-import-only paths that vanish after tree-shaking
//   - Re-exports referencing symbols that didn't make it into dist
//   - Re-introduction of a root `.` export (the symmetric layout
//     intentionally forbids one; a future change adding one back
//     should fail this script)
//   - Regression of the WOTS+ sunset split: WOTS+ classes must live at
//     `./deprecated/v1`, NOT in the live `./v1` barrel; the old WOTS+
//     subpaths must fail loudly.
import assert from "node:assert/strict";

console.log("  - live v1 barrel (shared surface only)...");
const live = await import("@quip.network/ethereum-sdk/v1");
assert(Array.isArray(live.walletFactoryAbi), "walletFactoryAbi missing from v1 barrel");
assert(typeof live.CANONICAL_ENTRYPOINT_V07 === "string", "CANONICAL_ENTRYPOINT_V07 missing");
assert(typeof live.computeUserOpHash === "function", "computeUserOpHash missing (userOpCodec)");
assert(typeof live.QuipError === "function", "QuipError missing from v1 barrel");
assert(live.QuipSigner === undefined, "QuipSigner leaked into the live v1 barrel — WOTS+ surface must stay in ./deprecated/v1");
assert(live.WotsCodec === undefined, "WotsCodec leaked into the live v1 barrel");
assert(live.deployerAbi === undefined, "deployerAbi leaked into the live v1 barrel — the Deployer is sunset WOTS+-era infra (live deploys go straight through CreateX)");

console.log("  - live v1 subpath exports...");
const liveErrors = await import("@quip.network/ethereum-sdk/v1/errors");
assert(typeof liveErrors.InvalidSignatureError === "function", "InvalidSignatureError via subpath");
const userOpCodec = await import("@quip.network/ethereum-sdk/v1/userOpCodec");
assert(typeof userOpCodec.packAccountGasLimits === "function", "packAccountGasLimits via userOpCodec subpath");

console.log("  - deprecated v1 barrel (WOTS+ surface)...");
const barrel = await import("@quip.network/ethereum-sdk/deprecated/v1");
assert(typeof barrel.QuipSigner === "function", "QuipSigner missing from deprecated/v1 barrel");
assert(typeof barrel.WOTSPlusImplementationClient === "function", "WOTSPlusImplementationClient missing");
assert(typeof barrel.QuipClient === "function", "QuipClient missing");
assert(typeof barrel.QuipPaymasterClient === "function", "QuipPaymasterClient missing");
assert(typeof barrel.WotsCodec === "object", "WotsCodec namespace missing");
assert(typeof barrel.WotsCodec.encodeInit === "function", "WotsCodec.encodeInit missing");
assert(Array.isArray(barrel.deployerAbi), "deployerAbi missing from deprecated/v1 barrel (sunset Deployer ABI must stay reachable)");
assert(barrel.KeyType.Transaction === 0, "KeyType enum wrong");
assert(typeof barrel.CANONICAL_ENTRYPOINT_V07 === "string", "CANONICAL_ENTRYPOINT_V07 missing (shared re-export)");
assert(typeof barrel.parseWalletReceipt === "function", "parseWalletReceipt missing");
assert(typeof barrel.parseWalletDeployed === "function", "parseWalletDeployed missing");
assert(typeof barrel.buildUserOp === "function", "buildUserOp missing");
assert(typeof barrel.WotsCodec.computeUserOpHash === "function", "computeUserOpHash missing from WotsCodec re-export surface");

console.log("  - deprecated v1 subpath exports...");
const errors = await import("@quip.network/ethereum-sdk/deprecated/v1/errors");
assert(typeof errors.KeyAlreadyBurnedError === "function", "KeyAlreadyBurnedError via deprecated subpath");
assert(typeof errors.InvalidSignatureError === "function", "shared error re-export via deprecated subpath");
const events = await import("@quip.network/ethereum-sdk/deprecated/v1/events");
assert(typeof events.parseWalletDeployed === "function", "parseWalletDeployed via subpath");
const directCodec = await import("@quip.network/ethereum-sdk/deprecated/v1").then((m) => m.WotsCodec);
assert(directCodec.WOTS_ELEMENTS_COUNT === 67, "codec constant wrong");

console.log("  - deprecated v0 barrel...");
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
for (const retired of ["v1/signer", "v1/walletClient", "v1/wotsCodec", "v1/events", "v1/userOp", "v0"]) {
  await assert.rejects(
    () => import(`@quip.network/ethereum-sdk/${retired}`),
    /ERR_PACKAGE_PATH_NOT_EXPORTED/,
    `retired subpath ./${retired} should no longer resolve (moved to ./deprecated/*)`
  );
}

console.log("  - signer + codec round-trip (no network)...");
const { QuipSigner, WotsCodec, createInMemoryBurnSet } = barrel;
assert(typeof createInMemoryBurnSet === "function", "createInMemoryBurnSet missing from barrel");
const quantumSecret = new Uint8Array(32).fill(0x01);
const vaultId = "0x" + "02".repeat(32);
const burnSet = createInMemoryBurnSet();
const signer = new QuipSigner(quantumSecret, burnSet.consume);
const disaster = signer.generateKeyPair(vaultId).publicKey;
const ownership = signer.generateKeyPair(vaultId).publicKey;
// Init payload is fixed-shape: 3 keysets of MAX_KEYS (=10) each plus the
// disaster and ownership keys. (1 + 1 + 10 + 10 + 10) * 64 = 2048 bytes.
const MAX_KEYS = WotsCodec.MAX_KEYS;
assert.equal(MAX_KEYS, 10, "MAX_KEYS drift — smoke check assumes 10");
const txKeys = Array.from({ length: MAX_KEYS }, () => signer.generateKeyPair(vaultId).publicKey);
const recoveryKeys = Array.from({ length: MAX_KEYS }, () => signer.generateKeyPair(vaultId).publicKey);
const verificationKeys = Array.from({ length: MAX_KEYS }, () => signer.generateKeyPair(vaultId).publicKey);
const initPayload = WotsCodec.encodeInit(disaster, ownership, txKeys, recoveryKeys, verificationKeys);
assert.equal(initPayload.length, 2 + WotsCodec.INIT_PAYLOAD_SIZE * 2, `init payload wrong size: ${initPayload.length}`);
const decoded = WotsCodec.decodeInit(initPayload);
assert.equal(decoded.transactionKeys.length, MAX_KEYS, "decoded tx-key count");
assert.equal(decoded.recoveryKeys.length, MAX_KEYS, "decoded recovery-key count");
assert.equal(decoded.verificationKeys.length, MAX_KEYS, "decoded verification-key count");
assert.equal(decoded.disasterRecoveryKey.publicSeed, disaster.publicSeed, "disaster seed round-trip");

console.log("  - sign + burn (no network)...");
const message = "0x" + "77".repeat(32);
// QuipSigner.sign is async (burn-set consumption goes through an async hook).
const sig = await signer.sign(message, vaultId, txKeys[0].publicSeed);
assert.equal(sig.length, 67, `sig length wrong: ${sig.length}`);
let burnErr;
try {
  await signer.sign(message, vaultId, txKeys[0].publicSeed);
} catch (e) {
  burnErr = e;
}
assert(burnErr, "second sign should have thrown");
assert(
  burnErr instanceof errors.KeyAlreadyBurnedError,
  `expected KeyAlreadyBurnedError, got ${burnErr?.constructor?.name}`,
);

console.log("OK");
