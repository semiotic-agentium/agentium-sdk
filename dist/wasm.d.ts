import { type InitInput } from '@semiotic-labs/agentium-sdk-wasm';
import type { VerificationResult, KeyPair } from './vc/types.js';
/**
 * Ensures the WASM module is loaded and ready.
 * Uses lazy initialization - only loads on first call.
 *
 * @param wasmUrl - Optional URL/path to the WASM binary. If not provided,
 *                  defaults to resolving `wasm_bg.wasm` relative to the JS module.
 *                  For browser usage with bundlers like Vite, you may need:
 *                  ```ts
 *                  import wasmUrl from 'wasm/wasm_bg.wasm?url';
 *                  await ensureWasmReady(wasmUrl);
 *                  ```
 * @returns Promise that resolves when WASM is ready
 */
export declare function ensureWasmReady(wasmUrl?: InitInput): Promise<void>;
/**
 * Initialize WASM logging to browser console.
 * Call once after ensureWasmReady() to enable debug output.
 */
export declare function initLogging(): void;
/**
 * Verify a JWT-VC against a public key.
 *
 * @param jwt - The JWT string to verify (compact format: header.payload.signature)
 * @param publicKeyJwk - The public key as JWK JSON string
 * @returns Verification result with validity status, decoded claims if valid, and structured error if invalid.
 *          On failure: `{ valid: false, error: { code, message, data? } }`.
 *          Error codes: `JWT_EXPIRED` (with `data.expiredAt`), `INVALID_JWT_FORMAT`, `INVALID_JWK`,
 *          `VERIFICATION_FAILED`, `CLAIMS_VALIDATION`, `SERIALIZATION_ERROR`, `DECODE_ERROR`.
 */
export declare function verifyJwt(jwt: string, publicKeyJwk: string): Promise<VerificationResult>;
/**
 * Generate a new Ed25519 key pair.
 *
 * @returns Key pair with private and public JWK strings
 * @throws {WasmVcError} If key generation or serialization fails.
 */
export declare function generateKeypair(): Promise<KeyPair>;
/**
 * Extract public key from a private JWK.
 *
 * @param privateKeyJwk - The private key as JWK JSON string
 * @returns The public key as JWK JSON string
 * @throws {WasmVcError} If the private key JWK is invalid or serialization fails.
 */
export declare function getPublicKey(privateKeyJwk: string): Promise<string>;
//# sourceMappingURL=wasm.d.ts.map