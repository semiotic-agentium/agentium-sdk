// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import init, {
  verify_jwt as wasmVerifyJwt,
  generate_keypair as wasmGenerateKeypair,
  get_public_key as wasmGetPublicKey,
  init_logging as wasmInitLogging,
  type InitInput,
} from '@semiotic-labs/agentium-wasm';
import type { VerificationResult, KeyPair } from './vc/types.js';

let wasmInitialized: Promise<void> | null = null;
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
export async function ensureWasmReady(wasmUrl?: InitInput): Promise<void> {
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
export function initLogging(): void {
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
 * @param checkExpiration - Whether to check if the JWT has expired (default: true)
 * @returns Verification result with validity status and decoded claims if valid
 */
export async function verifyJwt(
  jwt: string,
  publicKeyJwk: string,
  checkExpiration: boolean = true,
): Promise<VerificationResult> {
  await ensureWasmReady();
  return wasmVerifyJwt(jwt, publicKeyJwk, checkExpiration) as VerificationResult;
}

/**
 * Generate a new Ed25519 key pair.
 *
 * @returns Key pair with private and public JWK strings
 */
export async function generateKeypair(): Promise<KeyPair> {
  await ensureWasmReady();
  return wasmGenerateKeypair() as KeyPair;
}

/**
 * Extract public key from a private JWK.
 *
 * @param privateKeyJwk - The private key as JWK JSON string
 * @returns The public key as JWK JSON string
 */
export async function getPublicKey(privateKeyJwk: string): Promise<string> {
  await ensureWasmReady();
  return wasmGetPublicKey(privateKeyJwk);
}
