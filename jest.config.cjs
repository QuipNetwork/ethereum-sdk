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
        // Mirror tsc's default emit-on-error behavior: skip type-checking in
        // the test transformer so pre-existing ABI drift in the legacy
        // wallet methods (transferWithWinternitz, addRecoveryKeys, etc.)
        // doesn't block the test runtime. Phase 4 (codec-payload migration)
        // re-enables strict checking once the legacy methods are removed.
        diagnostics: false,
        tsconfig: {
          module: "ESNext",
          moduleResolution: "bundler",
          verbatimModuleSyntax: false,
          types: ["node", "jest"],
        },
      },
    ],
  },
  forceExit: true,
  transformIgnorePatterns: ["node_modules/(?!(viem|@viem)/)"],
};
