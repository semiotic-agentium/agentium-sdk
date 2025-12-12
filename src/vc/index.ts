// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

export type {
  CredentialSubject,
  VerifiableCredential,
  VcJwtClaims,
  VerificationResult,
  DidDocument,
  VerificationMethod,
  JsonWebKey,
  JwtHeader,
  KeyPair,
} from './types.js';

export { type VcStorage, createBrowserStorage, createMemoryStorage } from './storage.js';
