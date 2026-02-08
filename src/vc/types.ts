// SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
//
// SPDX-License-Identifier: BUSL-1.1

/**
 * Credential subject containing user identity and enrollment info.
 * Matches backend's MembershipCredentialSubject.
 */
export interface CredentialSubject {
  /** User's DID (did:pkh) */
  id: string;
  /** Enrollment timestamp (ISO 8601 format) */
  enrollmentTime: string;
}

/**
 * W3C Verifiable Credential structure.
 * Backend issues VCs using SSI library with this structure.
 */
export interface VerifiableCredential {
  /** JSON-LD context */
  '@context': string[];
  /** Credential types */
  type: string[];
  /** Issuer DID (as object with id) */
  issuer: { id: string };
  /** Issuance date (ISO 8601 format) */
  issuanceDate: string;
  /** Credential subject with user info */
  credentialSubject: CredentialSubject;
}

/**
 * JWT claims structure for W3C VC (as issued by backend).
 * The VC is nested under the 'vc' claim per JWT-VC spec.
 * This is returned directly from verification - matches backend exactly.
 */
export interface VcJwtClaims {
  /** The Verifiable Credential */
  vc: VerifiableCredential;
  /** Subject (user DID) */
  sub: string;
  /** Expiration time (Unix timestamp) */
  exp: number;
  /** Issued at time (Unix timestamp, optional) */
  iat?: number;
}

/**
 * Structured error returned in VerificationResult when verification fails.
 */
export interface VerificationError {
  /** Stable error code */
  code: VcErrorCode;
  /** Human-readable error message */
  message: string;
  /** Optional metadata (e.g., expiredAt for JWT_EXPIRED) */
  data?: { expiredAt?: string } | undefined;
}

/**
 * Result of JWT-VC verification from WASM module.
 */
export interface VerificationResult {
  /** Whether the signature is valid and claims passed validation */
  valid: boolean;
  /** JWT claims if verification succeeded (matches backend structure exactly) */
  claims?: VcJwtClaims | undefined;
  /** Structured error if verification failed */
  error?: VerificationError | undefined;
}

/**
 * W3C DID Document structure (subset of fields we need).
 */
export interface DidDocument {
  /** DID identifier (e.g., "did:web:api.agentium.network") */
  id: string;
  /** Verification methods containing public keys (camelCase per W3C spec) */
  verificationMethod: VerificationMethod[];
  /** Authentication method references */
  authentication?: string[];
}

/**
 * Verification method within a DID Document.
 */
export interface VerificationMethod {
  /** Full key ID (e.g., "did:web:api.agentium.network#key-1") */
  id: string;
  /** Key type (e.g., "JsonWebKey2020") */
  type: string;
  /** Controller DID */
  controller: string;
  /** Public key in JWK format */
  publicKeyJwk: JsonWebKey;
}

/**
 * JWT header structure for extracting key ID.
 */
export interface JwtHeader {
  /** Algorithm (e.g., "EdDSA") */
  alg: string;
  /** Token type (usually "JWT") */
  typ?: string;
  /** Key ID - references verification method in DID document */
  kid?: string;
}

/**
 * JSON Web Key structure for Ed25519 keys.
 */
export interface JsonWebKey {
  /** Key type (always "OKP" for Ed25519) */
  kty: string;
  /** Curve (always "Ed25519") */
  crv: string;
  /** Public key material (base64url encoded) */
  x: string;
  /** Private key material (base64url encoded) - only present in private keys */
  d?: string | undefined;
}

/**
 * Key pair returned from WASM generate_keypair().
 */
export interface KeyPair {
  /** Full JWK with private key material (keep secret!) */
  private_key: JsonWebKey;
  /** Public JWK (safe to share) */
  public_key: JsonWebKey;
}

// ─────────────────────────────────────────────────────────────────────────────
// WASM error object shape returned by VcError -> JsValue mapping
// ─────────────────────────────────────────────────────────────────────────────
export type VcErrorCode =
  | 'JWT_EXPIRED'
  | 'INVALID_JWT_FORMAT'
  | 'INVALID_JWK'
  | 'VERIFICATION_FAILED'
  | 'CLAIMS_VALIDATION'
  | 'SERIALIZATION_ERROR'
  | 'DECODE_ERROR'
  | 'KEY_GENERATION'
  | 'SIGNING_FAILED';

export interface JwtExpiredError {
  code: 'JWT_EXPIRED';
  message: string;
  data: { expiredAt: string };
}

export interface GenericVcError {
  code: Exclude<VcErrorCode, 'JWT_EXPIRED'>;
  message: string;
  data?: undefined;
}

export type WasmVcError = JwtExpiredError | GenericVcError;

export function isWasmVcError(e: unknown): e is WasmVcError {
  if (typeof e !== 'object' || e === null) return false;
  const anyE = e as { code?: unknown; message?: unknown };
  return typeof anyE.code === 'string' && typeof anyE.message === 'string';
}
