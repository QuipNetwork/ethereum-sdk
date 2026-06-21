/* tslint:disable */
/* eslint-disable */
export function shrincs_verify_stateless_action(parameter_set_id: string, expected_public_key_commitment_hex: string, public_key: any, context: any, signature: any): boolean;
export function shrincs_verify_stateless_raw(parameter_set_id: string, expected_public_key_commitment_hex: string, public_key: any, message_hex: string, signature: any): boolean;
export function supported_parameter_sets(): string[];
export function shrincsStatefulRotationMessageHash(parameter_set_id: string, expected_public_key_commitment_hex: string, current_public_key: any, context: any, next_key: any): string;
export function shrincsStatefulActionMessageHash(parameter_set_id: string, expected_public_key_commitment_hex: string, context: any): string;
export function shrincs_verify_stateful_action(parameter_set_id: string, expected_public_key_commitment_hex: string, public_key: any, context: any, signature: any): boolean;
export function shrincsFullRotationMessageHash(parameter_set_id: string, expected_public_key_commitment_hex: string, current_public_key: any, context: any, next_key: any): string;
export function shrincs_verify_stateful_raw(parameter_set_id: string, expected_public_key_commitment_hex: string, public_key: any, message_hex: string, signature: any): boolean;
export function shrincsStatelessActionMessageHash(parameter_set_id: string, expected_public_key_commitment_hex: string, context: any): string;
export function shrincsKeygen(parameter_set_id: string, seed_hex: string, max_stateful_signatures: number): WasmShrincsKeypair;
/**
 * Initialize Javascript logging and panic handler
 */
export function solana_program_init(): void;
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
  rotateFullKey(current_public_key: any, recovery_signature: any, next_key: any): boolean;
  enterRecoveryMode(caller_hex: string): void;
  rotateToFreshKey(current_public_key: any, recovery_signature: any, next_key: any): boolean;
  verifyStatefulAction(public_key: any, action_type_hex: string, payload_hash_hex: string, signature: any): boolean;
  verifyStatelessAction(public_key: any, action_type_hex: string, payload_hash_hex: string, signature: any): boolean;
  setStatefulPolicyLeafBitmap(caller_hex: string): void;
  setStatefulPolicyMonotonicIndex(caller_hex: string, initial_leaf_index: number): void;
  setStatefulPolicyRecoveryRotation(caller_hex: string): void;
  constructor(owner_hex: string, chain_id_hex: string, contract_address_hex: string, initial_public_key_commitment_hex: string);
  snapshot(): any;
}
export class WasmShrincsKeypair {
  private constructor();
  free(): void;
  publicKey(): any;
  signStatefulRaw(message_hex: string): any;
  exportSigningKey(): any;
  signStatelessRaw(message_hex: string): any;
  /**
   * Deterministically sign a raw message at a caller-chosen stateful leaf.
   *
   * Unlike `signStatefulRaw`, this does not advance the keypair's internal
   * leaf counter: the caller supplies `leaf` (typically the lowest unused
   * leaf read from the on-chain used-leaf bitmap). The on-chain verifier
   * requires `authPath.length == leaf`, so the SDK stays authoritative over
   * which leaf is burned.
   */
  signStatefulRawAt(message_hex: string, leaf: number): any;
}
