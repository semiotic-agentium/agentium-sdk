// SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
//
// SPDX-License-Identifier: BUSL-1.1

export type {
  CredentialSubject,
  VerifiableCredential,
  VcJwtClaims,
  VerificationResult,
  VerificationError,
  DidDocument,
  VerificationMethod,
  JsonWebKey,
  JwtHeader,
  KeyPair,
  VcErrorCode,
  WasmVcError,
} from './types.js';
export { isWasmVcError } from './types.js';

export { type VcStorage, createBrowserStorage, createMemoryStorage } from './storage.js';
