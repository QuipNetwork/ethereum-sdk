// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type Hex } from "viem";

import {
  CANONICAL_OPERATOR,
  LIVE_SALT_PREIMAGES,
  assertSaltLayout,
  senderGuardedRawSalt,
} from "../../internal/createxSalts.js";

// `assertSaltLayout` exists ONLY to throw: its own doc notes that taking the
// wrong CreateX branch "does not throw inside CreateX — it deploys successfully,
// at a different address." Every other test drives it through the happy path
// (`senderGuardedRawSalt`), so none of its throw branches are exercised and a
// refactor that silently dropped a check would pass. These pin the fail-closed
// behavior directly.
describe("assertSaltLayout (fail-closed guard)", () => {
  const OP = CANONICAL_OPERATOR;
  const ENTROPY_11 = "22".repeat(11);

  it("rejects a salt that is not 32 bytes", () => {
    expect(() => assertSaltLayout(OP, "0x1234" as Hex)).toThrow(
      /raw salt must be 32 bytes/
    );
  });

  it("rejects a salt whose leading 20 bytes are not the operator", () => {
    const wrong = `0x${"11".repeat(20)}00${ENTROPY_11}` as Hex;
    expect(() => assertSaltLayout(OP, wrong)).toThrow(
      /bytes 0-19 are not the operator/
    );
  });

  it("rejects a cross-chain (0x01) flag in byte 20", () => {
    const flagged = `0x${OP.slice(2).toLowerCase()}01${ENTROPY_11}` as Hex;
    expect(() => assertSaltLayout(OP, flagged)).toThrow(/byte 20 is not 0x00/);
  });

  it("accepts the layout senderGuardedRawSalt produces", () => {
    const salt = senderGuardedRawSalt(
      OP,
      LIVE_SALT_PREIMAGES.WalletFactoryProxy
    );
    expect(() => assertSaltLayout(OP, salt)).not.toThrow();
  });
});
