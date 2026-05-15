// Smoke check: runs inside the scratch project after the tarball is
// installed. Verifies the SDK's public surface is reachable and a
// purely-local code path executes correctly. No network access.
//
// What this catches that the in-repo tests don't:
//   - Missing `dist/` files (the `files` glob in package.json drifts)
//   - Broken subpath exports (`./v1/errors`, `./v1/events`, etc.)
//   - ESM/CJS interop regressions
//   - Type-import-only paths that vanish after tree-shaking
//   - Re-exports referencing symbols that didn't make it into dist
//   - Re-introduction of a root `.` export (the symmetric layout
//     intentionally forbids one; a future change adding one back
//     should fail this script)
import assert from "node:assert/strict";

console.log("  - v1 barrel...");
const barrel = await import("@quip.network/ethereum-sdk/v1");
assert(typeof barrel.QuipSigner === "function", "QuipSigner missing from v1 barrel");
assert(typeof barrel.QuipWalletClient === "function", "QuipWalletClient missing");
assert(typeof barrel.QuipClient === "function", "QuipClient missing");
assert(typeof barrel.QuipPaymasterClient === "function", "QuipPaymasterClient missing");
assert(typeof barrel.WotsCodec === "object", "WotsCodec namespace missing");
assert(typeof barrel.WotsCodec.encodeInit === "function", "WotsCodec.encodeInit missing");
assert(barrel.KeyType.Transaction === 0, "KeyType enum wrong");
assert(typeof barrel.CANONICAL_ENTRYPOINT_V07 === "string", "CANONICAL_ENTRYPOINT_V07 missing");
assert(typeof barrel.parseWalletReceipt === "function", "parseWalletReceipt missing");
assert(typeof barrel.parseQuipCreated === "function", "parseQuipCreated missing");
assert(typeof barrel.buildUserOp === "function", "buildUserOp missing");

console.log("  - v1 subpath exports...");
const errors = await import("@quip.network/ethereum-sdk/v1/errors");
assert(typeof errors.InvalidSignatureError === "function", "InvalidSignatureError via subpath");
const events = await import("@quip.network/ethereum-sdk/v1/events");
assert(typeof events.parseQuipCreated === "function", "parseQuipCreated via subpath");
// `WotsCodec` is namespace-re-exported from the barrel; check it's the same
// object referenced from a direct subpath import.
const directCodec = await import("@quip.network/ethereum-sdk/v1").then((m) => m.WotsCodec);
assert(directCodec.WOTS_ELEMENTS_COUNT === 67, "codec constant wrong");

console.log("  - v0 barrel...");
const v0 = await import("@quip.network/ethereum-sdk/v0");
assert(typeof v0.QuipSigner === "function", "QuipSigner missing from v0 barrel");
assert(typeof v0.QuipWalletClient === "function", "QuipWalletClient missing from v0 barrel");
assert(typeof v0.QuipClient === "function", "QuipClient missing from v0 barrel");
assert(typeof v0.QuipWallet__factory === "function", "QuipWallet__factory missing");
assert(typeof v0.QuipFactory__factory === "function", "QuipFactory__factory missing");
assert(typeof v0.QuipWallet__factory.connect === "function", "QuipWallet__factory.connect missing");
assert(v0.SUPPORTED_NETWORKS?.MAINNET === "mainnet", "v0 SUPPORTED_NETWORKS.MAINNET");
assert(v0.CHAIN_IDS?.ETHEREUM_MAINNET === 1, "v0 CHAIN_IDS.ETHEREUM_MAINNET");

console.log("  - root barrel rejected...");
await assert.rejects(
  () => import("@quip.network/ethereum-sdk"),
  /ERR_PACKAGE_PATH_NOT_EXPORTED/,
  "root import should fail loudly after symmetric split"
);

console.log("  - signer + codec round-trip (no network)...");
const { QuipSigner, WotsCodec, createInMemoryBurnSet } = barrel;
assert(typeof createInMemoryBurnSet === "function", "createInMemoryBurnSet missing from barrel");
const quantumSecret = new Uint8Array(32).fill(0x01);
const vaultId = "0x" + "02".repeat(32);
const burnSet = createInMemoryBurnSet();
const signer = new QuipSigner(quantumSecret, burnSet.consume);
const disaster = signer.generateKeyPair(vaultId).publicKey;
const ownership = signer.generateKeyPair(vaultId).publicKey;
const txKeys = Array.from({ length: 5 }, () => signer.generateKeyPair(vaultId).publicKey);
const recoveryKeys = Array.from({ length: 10 }, () => signer.generateKeyPair(vaultId).publicKey);
const initPayload = WotsCodec.encodeInit(disaster, ownership, txKeys, recoveryKeys);
// 1088 bytes = (1 + 1 + 5 + 10) * 64; hex string is 0x + 2176 chars.
assert.equal(initPayload.length, 2 + 1088 * 2, `init payload wrong size: ${initPayload.length}`);
const decoded = WotsCodec.decodeInit(initPayload);
assert.equal(decoded.transactionKeys.length, 5, "decoded tx-key count");
assert.equal(decoded.recoveryKeys.length, 10, "decoded recovery-key count");
assert.equal(decoded.disasterRecoveryKey.publicSeed, disaster.publicSeed, "disaster seed round-trip");

console.log("  - sign + burn (no network)...");
const message = "0x" + "77".repeat(32);
const sig = signer.sign(message, vaultId, txKeys[0].publicSeed);
assert.equal(sig.length, 67, `sig length wrong: ${sig.length}`);
try {
  signer.sign(message, vaultId, txKeys[0].publicSeed);
  throw new Error("second sign should have thrown");
} catch (e) {
  assert(e instanceof errors.KeyAlreadyBurnedError, `expected KeyAlreadyBurnedError, got ${e?.constructor?.name}`);
}

console.log("OK");
