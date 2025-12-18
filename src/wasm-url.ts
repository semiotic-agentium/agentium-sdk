// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

/**
 * Pre-configured WASM URL for the agentium SDK.
 *
 * This resolves to the WASM binary file location relative to this module.
 * Useful when you want the SDK to handle path resolution instead of manually
 * importing the WASM file.
 *
 * @example
 * ```typescript
 * import { ensureWasmReady } from '@semiotic-labs/agentium-sdk'
 * import { wasmUrl } from '@semiotic-labs/agentium-sdk/wasm-url'
 *
 * await ensureWasmReady(wasmUrl)
 * ```
 */
export const wasmUrl = new URL(
  '../packages/agentium-native/wasm/pkg/agentium_sdk_wasm_bg.wasm',
  import.meta.url,
).href;
