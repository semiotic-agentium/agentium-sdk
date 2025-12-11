// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

/**
 * Vitest setup file for loading WASM module in Node.js test environment.
 *
 * The WASM module is built with --target web which uses fetch() for loading.
 * In Node.js/Vitest, we use initSync() with the binary loaded from filesystem.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { initSync } from '@semiotic-labs/agentium-wasm';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load WASM binary from filesystem
const wasmPath = resolve(__dirname, 'packages/agentium-wasm/pkg/agentium_wasm_bg.wasm');
const wasmBinary = readFileSync(wasmPath);

// Initialize WASM synchronously before tests run
initSync({ module: wasmBinary });
