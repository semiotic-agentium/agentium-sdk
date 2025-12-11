// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

/**
 * Membership credential claims embedded in JWT-VC.
 */
export interface MembershipClaims {
  /** Privy user ID or wallet address */
  member_id: string;
  /** Membership status (e.g., "active") */
  status: string;
}

/**
 * Decoded JWT claims after successful verification.
 */
export interface DecodedClaims {
  /** Issuer DID (e.g., "did:web:api.agentium.network") */
  issuer: string;
  /** Subject identifier (user) */
  subject: string;
  /** Expiration time (Unix timestamp) */
  expires_at: number;
  /** Issued at time (Unix timestamp) */
  issued_at: number;
  /** Membership claims */
  membership: MembershipClaims;
}

/**
 * Result of JWT-VC verification from WASM module.
 */
export interface VerificationResult {
  /** Whether the signature is valid and claims passed validation */
  valid: boolean;
  /** Decoded claims if verification succeeded */
  claims?: DecodedClaims | undefined;
  /** Error message if verification failed */
  error?: string | undefined;
}

/**
 * W3C DID Document structure (subset of fields we need).
 * Note: Backend returns snake_case field names.
 */
export interface DidDocument {
  /** DID identifier (e.g., "did:web:api.agentium.network") */
  id: string;
  /** Verification methods containing public keys (snake_case from backend) */
  verification_method: VerificationMethod[];
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
  private_jwk: string;
  /** Public JWK (safe to share) */
  public_jwk: string;
}
