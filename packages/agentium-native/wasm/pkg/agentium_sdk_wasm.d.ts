/* tslint:disable */
/* eslint-disable */

/**
 * Generate a new Ed25519 key pair
 *
 * Returns a JSON object with `private_jwk` and `public_jwk` fields.
 * The private key should be stored securely and never exposed.
 */
export function generate_keypair(): any;

/**
 * Extract public key from a private JWK
 *
 * # Arguments
 * * `private_key_jwk` - The private key as JWK JSON string
 *
 * # Returns
 * The public key as JWK JSON string
 */
export function get_public_key(private_key_jwk: string): string;

/**
 * Initialize logging for the WASM module.
 *
 * This sets up `tracing` to output to the browser console via `tracing-wasm`.
 * Call this once before using any other functions from this library.
 */
export function init_logging(): void;

/**
 * Verify a JWT against a public key
 *
 * # Arguments
 * * `jwt` - The JWT string to verify (compact format: header.payload.signature)
 * * `public_key_jwk` - The public key as JWK JSON string
 * * `check_expiration` - Whether to check if the JWT has expired (default: true)
 *
 * # Returns
 * A VerificationResult with validity status and decoded claims if valid
 */
export function verify_jwt(jwt: string, public_key_jwk: string): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly generate_keypair: () => [number, number, number];
  readonly get_public_key: (a: number, b: number) => [number, number, number, number];
  readonly init_logging: () => void;
  readonly verify_jwt: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
