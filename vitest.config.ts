// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    // Load WASM binary synchronously before tests
    setupFiles: ['./vitest.setup.ts'],
  },
  server: {
    watch: {
      // Exclude Rust build artifacts from file watching
      ignored: ['**/packages/agentium-native/target/**'],
    },
  },
});
