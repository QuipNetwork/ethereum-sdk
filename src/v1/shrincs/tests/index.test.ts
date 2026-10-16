// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import * as SDK from "../index.js";
import type {
  ShrincsPaymasterClientParams,
  ShrincsWalletClientParams,
} from "../index.js";

// Barrel smoke test: guards the front-end consumer surface. If a key export is
// dropped or renamed in `index.ts`, this fails loudly at the SDK boundary.
describe("shrincs SDK barrel exports", () => {
  it("exports the core client/signer classes as constructors", () => {
    for (const name of [
      "ShrincsSigner",
      "ShrincsKeyPair",
      "ShrincsWalletClient",
      "ShrincsPaymasterClient",
      "ShrincsFactoryClient",
    ] as const) {
      expect(typeof (SDK as Record<string, unknown>)[name]).toBe("function");
    }
  });

  it("exports the WASM loader and V1 commitment helper as functions", () => {
    expect(typeof SDK.loadShrincsWasm).toBe("function");
    expect(typeof SDK.v1Commitment).toBe("function");
  });

  it("exports the codec namespace with its encoders", () => {
    expect(typeof SDK.ShrincsCodec).toBe("object");
    expect(typeof SDK.ShrincsCodec.encodeUserOpSignature).toBe("function");
    expect(typeof SDK.ShrincsCodec.decodeUserOpSignature).toBe("function");
    expect(typeof SDK.ShrincsCodec.domainSeparator).toBe("function");
  });

  it("exports the typed error classes", () => {
    expect(typeof SDK.StaleStatefulLeafError).toBe("function");
    expect(typeof SDK.CommitmentMismatchError).toBe("function");
    expect(typeof SDK.OwnerMismatchError).toBe("function");
    // They are constructible QuipError subclasses.
    expect(new SDK.StaleStatefulLeafError(2)).toBeInstanceOf(SDK.QuipError);
    expect(new SDK.CommitmentMismatchError()).toBeInstanceOf(SDK.QuipError);
    expect(
      new SDK.OwnerMismatchError(
        "0x00000000000000000000000000000000000000a1",
        "0x00000000000000000000000000000000000000b2"
      )
    ).toBeInstanceOf(SDK.QuipError);
  });

  it("exports the hash-suite constant", () => {
    expect(SDK.HASH_SUITE_KECCAK_256).toBe(1);
  });

  it("exports the event parsers and userOp builders", () => {
    expect(typeof SDK.parseWalletInitialized).toBe("function");
    expect(typeof SDK.parseUserOpSponsored).toBe("function");
    expect(typeof SDK.buildUserOp).toBe("function");
    expect(typeof SDK.signWalletUserOp).toBe("function");
  });

  it("exports the wallet and paymaster client constructor param types", () => {
    // Compile-time smoke: tsc fails if the barrel does not re-export these names.
    const walletParams: ShrincsWalletClientParams | null = null;
    const paymasterParams: ShrincsPaymasterClientParams | null = null;
    expect(walletParams).toBeNull();
    expect(paymasterParams).toBeNull();
  });
});
