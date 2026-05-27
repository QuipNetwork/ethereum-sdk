// Self-contained config for the test-sdk operator smoke scripts.
//
// EVERYTHING is hardcoded by design (RPC URL, private keys, contract
// addresses, quantum secrets, vault IDs). The scripts in this directory
// MUST NOT read from `.env` or any other ambient config — the goal is
// that you can `tsx test-sdk/createWallets.ts` from a fresh checkout
// with nothing but `npm install` having been run.
//
// All values target OP Sepolia (chainId 11155420) and the canonical Quip
// stack deployed via:
//   - make deploy-deployer-op-sepolia
//   - make deploy-all-op-sepolia
//   - make deploy-impl-op-sepolia
//   - make vet-impl-op-sepolia
//   - make deploy-dummy-erc20s-op-sepolia
//
// SAFETY: every private key below is a throwaway TEST KEY funded with
// trivial amounts on a public testnet. NEVER reuse these on mainnet.
import { keccak256, toBytes, type Address, type Hex } from "viem";
import { optimismSepolia } from "viem/chains";

export const CHAIN = optimismSepolia;
export const CHAIN_ID: number = optimismSepolia.id; // 11155420
export const RPC_URL: string =
  "https://opt-sepolia.g.alchemy.com/v2/nQYdtBs5tZpoBRdBsZwgb";

// ---------------------------------------------------------------------------
// On-chain deployed contracts (CREATE3-deterministic addresses; same on
// every chain reached by the canonical Deployer + canonical salts).
// ---------------------------------------------------------------------------
export const QUIP_FACTORY: Address =
  "0xE567d318819c067c26fC1E44D04beD2b4FE93BCC";
// Vetted QuipWallet implementation registered on the factory. We don't call
// this directly — `factory.deployLatestWalletProxy(...)` picks it via
// `latestWalletImpl`. Stored here only for human reference.
export const QUIP_WALLET_IMPL: Address =
  "0x81648CBFA79aD8f2c4A59E0DdeA03b1BC8b34cfb";
// DummyQuipERC20 with 6 decimals (symbol "tQ6"). Permissionless `mint`,
// no Ownable, no faucet — anyone can mint to anyone.
// viem validates EIP-55 checksums strictly — use the casing from
// `cast to-check-sum-address` exactly. The lowercase form is
// 0x154fa1b00d28a200f1afa75378d0ae6735252248.
export const TQ6: Address = "0x154fA1B00D28a200F1AFA75378d0Ae6735252248";
export const TQ6_DECIMALS = 6;

// ---------------------------------------------------------------------------
// Test EOAs.
// ---------------------------------------------------------------------------
// Wallet 1: the operator EOA that already has 0.2 OP Sepolia ETH. Also
// reuses the same private key as `.env:PRIVATE_KEY` (because that's the
// EOA we've been deploying from), but we hardcode it here to keep
// test-sdk independent of `.env`.
export const WALLET_1_PRIVATE_KEY: Hex =
  "0xd626042bab89368ff948d78c81736a7027e74cdd069d7d0b615260e8cf93cccd";
export const WALLET_1_ADDRESS: Address =
  "0x83918c4Cc5DaC3A70Cf48d91357C4dC5CBD1AC9f";

// Wallet 2: fresh throwaway EOA, currently 0 balance — `createWallets.ts`
// auto-funds it with a tiny amount of ETH from wallet 1 before doing
// anything else.
export const WALLET_2_PRIVATE_KEY: Hex =
  "0xc1b56b9e0b72684b684de5c86bb43ece786f7028bceec8abb726f657af4441bd";
export const WALLET_2_ADDRESS: Address =
  "0x3361C92fF1f9b08137296244c81ba519a8Ce30a2";

// One-time ETH transfer from wallet 1 → wallet 2 if wallet 2 is empty.
// Enough to cover wallet 2's own QuipWallet creation + a couple of
// follow-up txs on OP Sepolia where gas is fractions of a cent.
export const WALLET_2_FUND_AMOUNT_WEI: bigint = 10_000_000_000_000_000n; // 0.01 ETH

// ---------------------------------------------------------------------------
// Per-EOA WOTS+ keying material. The `quantumSecret` is the user's seed-
// phrase analog — every WOTS+ keypair the user ever uses is deterministically
// derived from `(quantumSecret, vaultId, publicSeed)`. We hardcode both so
// re-runs of the scripts always derive the same on-chain wallets without
// needing any state file.
//
// PRODUCTION NOTE: in a real deployment `quantumSecret` is per-user secret
// material on the order of importance of a BIP39 mnemonic. It MUST be
// generated with a CSPRNG and stored in durable, encrypted user storage.
// Re-deriving from a string label like "quip.test-sdk..." is acceptable
// here ONLY because every key derived is single-use, on a throwaway
// testnet, with no real funds at stake.
export const WALLET_1_QUANTUM_SECRET: Hex = keccak256(
  toBytes("quip.test-sdk.quantum-secret.wallet-1.v1")
);
export const WALLET_2_QUANTUM_SECRET: Hex = keccak256(
  toBytes("quip.test-sdk.quantum-secret.wallet-2.v1")
);
// Vault IDs (per-wallet branch under a given quantumSecret). Any unique
// 32-byte value works; we use a deterministic string-derived hash so re-
// runs always target the same vault.
export const WALLET_1_VAULT_ID: Hex = keccak256(
  toBytes("quip.test-sdk.vault.wallet-1.v1")
);
export const WALLET_2_VAULT_ID: Hex = keccak256(
  toBytes("quip.test-sdk.vault.wallet-2.v1")
);

// ---------------------------------------------------------------------------
// ERC20 mechanics.
// ---------------------------------------------------------------------------
// 10 tQ6 in raw units (6 decimals).
export const TRANSFER_AMOUNT_TQ6: bigint = 10n * 10n ** BigInt(TQ6_DECIMALS);
// Top up wallet 1's Quip wallet with this much tQ6 if its balance is
// below `TRANSFER_AMOUNT_TQ6`. Generous buffer so the transfer flow
// works for many re-runs without re-minting every time.
export const TQ6_TOPUP_AMOUNT: bigint = 1_000n * 10n ** BigInt(TQ6_DECIMALS);

// Minimal ERC20 ABI fragment — only `mint`, `transfer`, `balanceOf`,
// `decimals`, `symbol`. The DummyQuipERC20 supports all of these.
export const ERC20_ABI = [
  {
    type: "function",
    name: "mint",
    stateMutability: "nonpayable",
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "transfer",
    stateMutability: "nonpayable",
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "decimals",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    type: "function",
    name: "symbol",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "string" }],
  },
] as const;
