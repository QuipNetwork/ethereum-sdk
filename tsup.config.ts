import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["index.ts", "src/addresses.ts"],
  format: ["esm"],
  dts: false,
  clean: true,
  bundle: true,
  platform: "node",
  external: [
    "ethers",
    "@noble/hashes",
    "@noble/hashes/*",
    "@noble/ciphers",
    "@noble/ciphers/*",
    "@quip.network/hashsigs",
    "@quip.network/hashsigs-solidity",
    "@midl/core",
    "@midl/connectors",
    "@midl/react",
    "alchemy-sdk",
    "hardhat",
    "hardhat/*",
    "fsevents",
    "chokidar",
  ],
  noExternal: ["typechain-types"],
  esbuildOptions(options) {
    options.resolveExtensions = [".ts", ".js", ".mjs", ".json"];
  },
});
