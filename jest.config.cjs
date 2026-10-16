module.exports = {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  testMatch: ["**/src/**/*.test.ts"],
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        useESM: true,
        tsconfig: {
          module: "ESNext",
          moduleResolution: "bundler",
          verbatimModuleSyntax: false,
          // Per-file transpile. ts-jest's whole-program diagnostics do not
          // honor `module: ESNext` and reject the runtime-required
          // `import ... with { type: "json" }` attribute in src/v1/addresses.ts
          // with TS2823. isolatedModules transpiles each file on its own, so
          // the JSON import attribute passes. `tsc --noEmit` stays the type
          // gate.
          isolatedModules: true,
          types: ["node", "jest"],
        },
      },
    ],
  },
  forceExit: true,
  transformIgnorePatterns: ["node_modules/(?!(viem|@viem)/)"],
  // In-tree so CI can persist it: GitLab only caches paths under the project
  // dir, and the default (os tmpdir) is lost between jobs, which makes every
  // job re-transpile the whole suite through ts-jest. Entries are keyed by
  // file content + config hash, so a stale cache is skipped, never wrong.
  cacheDirectory: "<rootDir>/.ci/jest",
};
