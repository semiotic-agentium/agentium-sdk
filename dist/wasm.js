// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT
import init, { verify_jwt as wasmVerifyJwt, generate_keypair as wasmGenerateKeypair, get_public_key as wasmGetPublicKey, init_logging as wasmInitLogging, } from '@semiotic-labs/agentium-sdk-wasm';
let wasmInitialized = null;
let loggingInitialized = false;
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
export async function ensureWasmReady(wasmUrl) {
    if (wasmInitialized === null) {
        wasmInitialized = init(wasmUrl).then(() => {
            // Module loaded successfully
        });
    }
    await wasmInitialized;
}
/**
 * Initialize WASM logging to browser console.
 * Call once after ensureWasmReady() to enable debug output.
 */
export function initLogging() {
    if (!loggingInitialized) {
        wasmInitLogging();
        loggingInitialized = true;
    }
}
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
export async function verifyJwt(jwt, publicKeyJwk) {
    await ensureWasmReady();
    return wasmVerifyJwt(jwt, publicKeyJwk);
}
/**
 * Generate a new Ed25519 key pair.
 *
 * @returns Key pair with private and public JWK strings
 * @throws {WasmVcError} If key generation or serialization fails.
 */
export async function generateKeypair() {
    await ensureWasmReady();
    return wasmGenerateKeypair();
}
/**
 * Extract public key from a private JWK.
 *
 * @param privateKeyJwk - The private key as JWK JSON string
 * @returns The public key as JWK JSON string
 * @throws {WasmVcError} If the private key JWK is invalid or serialization fails.
 */
export async function getPublicKey(privateKeyJwk) {
    await ensureWasmReady();
    return wasmGetPublicKey(privateKeyJwk);
}
//# sourceMappingURL=wasm.js.map