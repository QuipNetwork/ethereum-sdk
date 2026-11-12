// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// WalletConnect transport budget (QUI-1328). A wallet app returns an ERC-1271
// signature to a dApp as the hex `result` of a JSON-RPC response. WalletConnect
// seals that JSON (ChaCha20-Poly1305, type-0 envelope) and base64-encodes it,
// and the relay caps the encoded message. This file measures the real wire
// size with WalletConnect's own sealing code.
//
// Two layers:
//   - always on: the sealed size against the cap recorded in QUI-1328;
//   - opt-in (`WALLETCONNECT_PROJECT_ID` set): the signature is pushed through
//     the real relay between two in-process clients, which measures the cap
//     instead of trusting the recorded number.

import { describe, it, expect } from "@jest/globals";
import { SignClient } from "@walletconnect/sign-client";
import { encrypt, generateRandomBytes32 } from "@walletconnect/utils";
import { type Hex, size } from "viem";

import { ERC1271_SIGNATURE_BYTES } from "../constants.js";

/// Relay publish cap in bytes as recorded in QUI-1328 (104 KiB). Not confirmed
/// by WalletConnect documentation; the opt-in relay test below is the check.
const RELAY_MESSAGE_CAP_BYTES = 106_496;
/// Pre-0.4.0 ABI-encoded ERC-1271 signature (pinned in `shrincsCodec.test.ts`).
const LEGACY_SIGNATURE_BYTES = 91_840;

const signatureOf = (bytes: number): Hex => ("0x" + "ab".repeat(bytes)) as Hex;

/// The relay message carrying `signature` as a JSON-RPC result, sealed exactly
/// as the WalletConnect client seals it.
function sealedResponseBytes(signature: Hex): number {
  const message = JSON.stringify({
    id: 1_700_000_000_000_000,
    jsonrpc: "2.0",
    result: signature,
  });
  return encrypt({ symKey: generateRandomBytes32(), message }).length;
}

describe("WalletConnect transport budget", () => {
  it.each([
    { name: "one fixed-layout signature", bytes: ERC1271_SIGNATURE_BYTES, fits: true },
    { name: "two fixed-layout signatures in one message", bytes: 2 * ERC1271_SIGNATURE_BYTES, fits: false },
    { name: "one pre-0.4.0 ABI signature", bytes: LEGACY_SIGNATURE_BYTES, fits: false },
  ])("$name: fits the relay cap = $fits", ({ bytes, fits }) => {
    const wire = sealedResponseBytes(signatureOf(bytes));
    expect(wire <= RELAY_MESSAGE_CAP_BYTES).toBe(fits);
  });

  it("one signature leaves at least 20% of the cap unused", () => {
    const wire = sealedResponseBytes(signatureOf(ERC1271_SIGNATURE_BYTES));
    expect(wire).toBeLessThan(RELAY_MESSAGE_CAP_BYTES * 0.8);
  });
});

const projectId = process.env.WALLETCONNECT_PROJECT_ID;
const describeRelay = projectId ? describe : describe.skip;

describeRelay("WalletConnect live relay", () => {
  const CHAIN = "eip155:8453";
  const ACCOUNT = `${CHAIN}:0x5B38Da6a701c568545dCfcB03FcB875f56beddC4`;
  const namespace = {
    chains: [CHAIN],
    methods: ["personal_sign"],
    events: ["accountsChanged"],
  };

  /// Opens a session between a dApp client and a wallet client over the real
  /// relay. The wallet answers every signing request with `respondWith()`.
  async function openSession(respondWith: () => Hex) {
    const client = (name: string) =>
      SignClient.init({
        projectId,
        metadata: { name, description: name, url: "https://quip.network", icons: [] },
        storageOptions: { database: ":memory:" },
      });
    const [dapp, wallet] = await Promise.all([client("quip-test-dapp"), client("quip-test-wallet")]);

    wallet.on("session_proposal", async ({ id }) => {
      await wallet.approve({
        id,
        namespaces: { eip155: { ...namespace, accounts: [ACCOUNT] } },
      });
    });
    wallet.on("session_request", async ({ topic, id }) => {
      await wallet.respond({
        topic,
        response: { id, jsonrpc: "2.0", result: respondWith() },
      });
    });

    const { uri, approval } = await dapp.connect({ optionalNamespaces: { eip155: namespace } });
    await wallet.pair({ uri: uri! });
    const session = await approval();
    const request = () =>
      dapp.request<Hex>({
        topic: session.topic,
        chainId: CHAIN,
        request: { method: "personal_sign", params: ["0x00", ACCOUNT] },
      });
    const close = async () => {
      await Promise.allSettled([dapp.core.relayer.transportClose(), wallet.core.relayer.transportClose()]);
    };
    return { request, close };
  }

  it("delivers one fixed-layout signature to the dApp intact", async () => {
    const signature = signatureOf(ERC1271_SIGNATURE_BYTES);
    const { request, close } = await openSession(() => signature);
    try {
      const received = await request();
      expect(size(received)).toBe(ERC1271_SIGNATURE_BYTES);
      expect(received).toBe(signature);
    } finally {
      await close();
    }
  }, 120_000);
});
