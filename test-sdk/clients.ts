// Per-EOA viem clients + QuipSigner factory.
//
// Constructs the lower-level primitives every other script in this
// directory needs:
//   - `publicClient` for reads
//   - `walletClient` with a signing `account` for writes
//   - `QuipSigner` keyed off the per-EOA `quantumSecret` for WOTS+ ops
//   - In-memory burn set (single-process, per-script-run)
//
// We deliberately AVOID `QuipClient` from `factoryClient.ts` because that
// class is built around an EIP-1193 provider (browser-style). In a Node
// script we already have viem's `privateKeyToAccount` doing local signing,
// so we use the same construction path as the SDK's own anvil tests
// (see `src/v1/tests/utils/anvilFixture.ts` ~line 446) — direct
// `QuipWalletClient` construction with viem clients.
import {
  createPublicClient,
  createWalletClient,
  http,
  hexToBytes,
  type Account,
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { nonceManager } from "viem/nonce";

import { QuipSigner } from "../src/v1/signer.js";
import { createInMemoryBurnSet } from "../src/v1/burnSet.js";

import { CHAIN, RPC_URL } from "./config.js";

export interface EoaClients {
  /// EOA address (the operator who pays gas and "owns" the Quip wallet).
  address: Address;
  /// The viem `Account` (LocalAccount) carrying the actual signing
  /// capability. We expose it separately from `address` because the
  /// `QuipWalletClient` constructor types its 6th argument as
  /// `Address`, but at runtime viem also accepts an `Account` object
  /// there — and we MUST hand in the object form on hosted RPCs (e.g.
  /// Alchemy) that reject `eth_sendTransaction`. Passing the address
  /// string makes viem treat it as a JSON-RPC account and route via
  /// `eth_sendTransaction`; passing the `Account` makes viem sign
  /// locally and route via `eth_sendRawTransaction`. Construction
  /// sites pass `account as unknown as Address`.
  account: Account;
  /// Viem public client for reads.
  publicClient: PublicClient;
  /// Viem wallet client with the EOA's private key for writes.
  walletClient: WalletClient;
  /// WOTS+ signer for this EOA, keyed off its hardcoded `quantumSecret`.
  quipSigner: QuipSigner;
}

/**
 * Build a fully-configured client bundle for one EOA. The `quantumSecret`
 * is converted from `Hex` to `Uint8Array` because `QuipSigner` expects raw
 * bytes (`keccak256(quantumSecret)` is the actual derivation root inside
 * the signer; see `src/v1/signer.ts:107`).
 *
 * Each call creates a FRESH in-memory burn set. That's fine for our
 * single-script-run pattern because:
 *   - WOTS+ keys are one-time-use, but the chain itself enforces this
 *     (key rotation on every `execute`), so a stale burn set can't cause
 *     a real key reuse — only a `KeyAlreadyBurnedError` in-process.
 *   - We never run two scripts in the same Node process.
 */
export function makeClients(params: {
  privateKey: Hex;
  expectedAddress: Address;
  quantumSecret: Hex;
}): EoaClients {
  // `nonceManager: nonceManager` (the singleton from viem/nonce) tracks
  // pending nonces locally per address. Without this, back-to-back
  // `walletClient.sendTransaction` / `writeContract` calls from the same
  // EOA inside one script race the node's `eth_getTransactionCount` —
  // the second tx reuses the first tx's nonce and the RPC rejects with
  // "replacement transaction underpriced". The singleton is process-
  // scoped, so it correctly serialises both wallet 1 and wallet 2 even
  // though they share no other state.
  const account = privateKeyToAccount(params.privateKey, { nonceManager });
  if (account.address.toLowerCase() !== params.expectedAddress.toLowerCase()) {
    throw new Error(
      `Private key ↔ address mismatch for ${params.expectedAddress}: ` +
        `key derives ${account.address}. Check test-sdk/config.ts.`
    );
  }
  // viem v2 PublicClient/WalletClient types vary slightly with the chain
  // generic; the unknown→typed cast keeps the public surface clean for
  // downstream callers without leaking chain-generic complexity.
  const publicClient = createPublicClient({
    chain: CHAIN,
    transport: http(RPC_URL),
  }) as unknown as PublicClient;

  const walletClient = createWalletClient({
    account,
    chain: CHAIN,
    transport: http(RPC_URL),
  }) as unknown as WalletClient;

  const burnSet = createInMemoryBurnSet();
  const quipSigner = new QuipSigner(hexToBytes(params.quantumSecret), burnSet.consume);

  return {
    address: account.address,
    account,
    publicClient,
    walletClient,
    quipSigner,
  };
}
