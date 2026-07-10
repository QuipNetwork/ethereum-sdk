/* tslint:disable */
/* eslint-disable */
export function shrincsKeygen(seed_hex: string, max_stateful_signatures: number): WasmShrincsKeypair;
export function shrincsVerifyStatelessAction(expected_public_key_commitment_hex: string, public_key: ShrincsPublicKey, context: ActionContext, signature: StatelessSignature): boolean;
export function shrincsVerifyStatefulRaw(expected_public_key_commitment_hex: string, public_key: ShrincsPublicKey, message_hex: string, signature: StatefulSignature): boolean;
export function shrincsFullRotationMessageHash(expected_public_key_commitment_hex: string, current_public_key: ShrincsPublicKey, context: RotationContext, next_key: RotationTarget): string;
export function shrincsStatefulRotationMessageHash(expected_public_key_commitment_hex: string, current_public_key: ShrincsPublicKey, context: RotationContext, next_key: StatefulRotationTarget): string;
export function shrincsStatefulActionMessageHash(expected_public_key_commitment_hex: string, context: ActionContext): string;
export function shrincsStatelessActionMessageHash(expected_public_key_commitment_hex: string, context: ActionContext): string;
export function shrincsVerifyStatefulAction(expected_public_key_commitment_hex: string, public_key: ShrincsPublicKey, context: ActionContext, signature: StatefulSignature): boolean;
export function shrincsVerifyStatelessRaw(expected_public_key_commitment_hex: string, public_key: ShrincsPublicKey, message_hex: string, signature: StatelessSignature): boolean;
/**
 * Initialize Javascript logging and panic handler
 */
export function solana_program_init(): void;
export interface HypertreeLayerSignature {
    treeIndex: bigint;
    leafIndex: number;
    wotsCPkHash: string;
    wotsCSignature: WotsCSignature;
    authPath: string[];
}

export interface ShrincsPublicKey {
    statefulPublicKey: string;
    publicKeyCommitment: string;
    pkSeed: string;
    hypertreeRoot: string;
}

export interface RotationTarget {
    statefulPublicKey: string;
    publicKeyCommitment: string;
    pkSeed: string;
    hypertreeRoot: string;
}

export interface WotsCSignature {
    randomizer: string;
    counter: number;
    chains: string[];
}

export interface StatefulSignature {
    randomizer: string;
    counter: number;
    chains: string[];
    authPath: string[];
}

export interface ActionContext {
    domainSeparator: string;
    nonce: string;
    keyVersion: string;
    actionType: string;
    payloadHash: string;
}

export interface ForsEntry {
    secretLeaf: string;
    authPath: string[];
}

export interface StatefulRotationTarget {
    statefulPublicKey: string;
    publicKeyCommitment: string;
}

export interface RotationContext {
    domainSeparator: string;
    nonce: string;
    keyVersion: string;
}

export interface StatelessSignature {
    fors: ForsSignature;
    hypertree: HypertreeLayerSignature[];
}

export interface ShrincsExportedSigningKey {
    statefulSkSeed: string;
    statefulPrfSeed: string;
    statefulPkSeed: string;
    statefulRoot: string;
    maxStatefulSignatures: number;
    nextStatefulLeafIndex: number;
    statelessSkSeed: string;
    statelessPrfSeed: string;
    pkSeed: string;
    hypertreeRoot: string;
}

export interface ForsSignature {
    randomizer: string;
    counter: number;
    entries: ForsEntry[];
}

export interface ShrincsAccountSnapshot {
    currentShrincsPublicKey: string;
    owner: string;
    chainId: string;
    contractAddress: string;
    domainSeparator: string;
    nonce: string;
    keyVersion: string;
    statelessSignaturesUsed: bigint;
    statefulPolicy: string;
    nextStatefulLeafIndex: number;
    recoveryMode: boolean;
}

/**
 * A hash; the 32-byte output of a hashing algorithm.
 *
 * This struct is used most often in `solana-sdk` and related crates to contain
 * a [SHA-256] hash, but may instead contain a [blake3] hash.
 *
 * [SHA-256]: https://en.wikipedia.org/wiki/SHA-2
 * [blake3]: https://github.com/BLAKE3-team/BLAKE3
 */
export class Hash {
  free(): void;
  /**
   * Create a new Hash object
   *
   * * `value` - optional hash as a base58 encoded string, `Uint8Array`, `[number]`
   */
  constructor(value: any);
  /**
   * Checks if two `Hash`s are equal
   */
  equals(other: Hash): boolean;
  /**
   * Return the `Uint8Array` representation of the hash
   */
  toBytes(): Uint8Array;
  /**
   * Return the base58 string representation of the hash
   */
  toString(): string;
}
/**
 * wasm-bindgen version of the Instruction struct.
 * This duplication is required until https://github.com/rustwasm/wasm-bindgen/issues/3671
 * is fixed. This must not diverge from the regular non-wasm Instruction struct.
 */
export class Instruction {
  private constructor();
  free(): void;
}
export class Instructions {
  free(): void;
  constructor();
  push(instruction: Instruction): void;
}
/**
 * wasm-bindgen version of the Message struct.
 * This duplication is required until https://github.com/rustwasm/wasm-bindgen/issues/3671
 * is fixed. This must not diverge from the regular non-wasm Message struct.
 */
export class Message {
  private constructor();
  free(): void;
  /**
   * The id of a recent ledger entry.
   */
  recent_blockhash: Hash;
}
/**
 * The address of a [Solana account][acc].
 *
 * Some account addresses are [ed25519] public keys, with corresponding secret
 * keys that are managed off-chain. Often, though, account addresses do not
 * have corresponding secret keys &mdash; as with [_program derived
 * addresses_][pdas] &mdash; or the secret key is not relevant to the operation
 * of a program, and may have even been disposed of. As running Solana programs
 * can not safely create or manage secret keys, the full [`Keypair`] is not
 * defined in `solana-program` but in `solana-sdk`.
 *
 * [acc]: https://solana.com/docs/core/accounts
 * [ed25519]: https://ed25519.cr.yp.to/
 * [pdas]: https://solana.com/docs/core/cpi#program-derived-addresses
 * [`Keypair`]: https://docs.rs/solana-sdk/latest/solana_sdk/signer/keypair/struct.Keypair.html
 */
export class Pubkey {
  free(): void;
  /**
   * Create a new Pubkey object
   *
   * * `value` - optional public key as a base58 encoded string, `Uint8Array`, `[number]`
   */
  constructor(value: any);
  /**
   * Derive a Pubkey from another Pubkey, string seed, and a program id
   */
  static createWithSeed(base: Pubkey, seed: string, owner: Pubkey): Pubkey;
  /**
   * Find a valid program address
   *
   * Returns:
   * * `[PubKey, number]` - the program address and bump seed
   */
  static findProgramAddress(seeds: any[], program_id: Pubkey): any;
  /**
   * Derive a program address from seeds and a program id
   */
  static createProgramAddress(seeds: any[], program_id: Pubkey): Pubkey;
  /**
   * Checks if two `Pubkey`s are equal
   */
  equals(other: Pubkey): boolean;
  /**
   * Return the `Uint8Array` representation of the public key
   */
  toBytes(): Uint8Array;
  /**
   * Return the base58 string representation of the public key
   */
  toString(): string;
  /**
   * Check if a `Pubkey` is on the ed25519 curve.
   */
  isOnCurve(): boolean;
}
export class WasmShrincsAccount {
  free(): void;
  rotateFullKey(current_public_key: ShrincsPublicKey, recovery_signature: StatelessSignature, next_key: RotationTarget): boolean;
  enterRecoveryMode(caller_hex: string): void;
  rotateToFreshKey(current_public_key: ShrincsPublicKey, recovery_signature: StatelessSignature, next_key: StatefulRotationTarget): boolean;
  verifyStatefulAction(public_key: ShrincsPublicKey, action_type_hex: string, payload_hash_hex: string, signature: StatefulSignature): boolean;
  verifyStatelessAction(public_key: ShrincsPublicKey, action_type_hex: string, payload_hash_hex: string, signature: StatelessSignature): boolean;
  setStatefulPolicyLeafBitmap(caller_hex: string): void;
  setStatefulPolicyMonotonicIndex(caller_hex: string, initial_leaf_index: number): void;
  setStatefulPolicyRecoveryRotation(caller_hex: string): void;
  constructor(owner_hex: string, chain_id_hex: string, contract_address_hex: string, initial_public_key_commitment_hex: string);
  snapshot(): ShrincsAccountSnapshot;
}
export class WasmShrincsKeypair {
  private constructor();
  free(): void;
  publicKey(): ShrincsPublicKey;
  signStatefulRaw(message_hex: string): StatefulSignature;
  exportSigningKey(): ShrincsExportedSigningKey;
  signStatelessRaw(message_hex: string): StatelessSignature;
  /**
   * Deterministically sign a raw message at a caller-chosen stateful leaf.
   *
   * Unlike `signStatefulRaw`, this does not advance the keypair's internal
   * leaf counter: the caller supplies `leaf` (typically the lowest unused
   * leaf read from the on-chain used-leaf bitmap). The on-chain verifier
   * requires `authPath.length == leaf`, so the SDK stays authoritative over
   * which leaf is burned.
   */
  signStatefulRawAt(message_hex: string, leaf: number): StatefulSignature;
}
