// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import globals from 'globals';
import pluginJs from '@eslint/js';
import tseslint from 'typescript-eslint';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';

export default tseslint.config(
  {
    // Top-level ignores for all files
    ignores: [
      'dist/',
      'docs/',
      'node_modules/',
      'package-lock.json',
      'vitest.config.ts', // Vitest config may have different globals/syntax
      '*.cjs', // CommonJS config files like jest.config.cjs
    ],
  },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        ...globals.node,
      },
      parserOptions: {
        ecmaVersion: 'latest', // Use 'latest' for future-proofing
        sourceType: 'module',
      },
    },
    rules: {
      // Add any project-specific ESLint rules here
      // Example: 'indent': ['error', 2],
      // Example: 'linebreak-style': ['error', 'unix'],
      // Example: 'quotes': ['error', 'single'],
      // Example: 'semi': ['error', 'always'],
    },
  },
  eslintPluginPrettierRecommended, // Ensure Prettier runs last to handle formatting
);
