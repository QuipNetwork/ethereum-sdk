// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
} from "viem";

import { ShrincsHdDerivationError } from "../errors.js";
import { ShrincsPaymasterClient } from "../shrincsPaymasterClient.js";
import { ShrincsSigner } from "../shrincsSigner.js";

const PAYMASTER = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" as Address;
const ACCOUNT = "0x00000000000000000000000000000000000000a1" as Address;
const COMMITMENT = ("0x" + "11".repeat(32)) as Hex;
const CHAIN_ID = 31337;

describe("ShrincsPaymasterClient derivationIndex", () => {
  it("throws ShrincsHdDerivationError when derivationIndex is -1", async () => {
    const signer = await ShrincsSigner.create(
      new TextEncoder().encode("any master (hd seed padding)")
    );
    expect(
      () =>
        new ShrincsPaymasterClient({
          paymasterAddress: PAYMASTER,
          publicClient: {} as PublicClient,
          walletClient: {} as WalletClient,
          signer,
          commitment: COMMITMENT,
          derivationIndex: -1,
          chainId: CHAIN_ID,
          account: ACCOUNT,
        })
    ).toThrow(ShrincsHdDerivationError);
  });
});
