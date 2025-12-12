// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

/**
 * Test helpers for VC integration tests.
 * Uses jose library for Ed25519 JWT signing.
 * Generates W3C-compliant VCs matching backend SSI implementation.
 */

import * as jose from 'jose';
import type { DidDocument, CredentialSubject, VerifiableCredential, JsonWebKey } from './types.js';

/**
 * Test keypair with JWK strings (matching WASM output format).
 */
export interface TestKeyPair {
  privateJwk: string;
  publicJwk: string;
}

/**
 * Options for issuing a test JWT-VC.
 */
export interface IssueJwtOptions {
  /** Issuer DID (e.g., did:web:api.agentium.network) */
  issuerDid: string;
  /** Subject DID (e.g., did:pkh:eip155:1:0x...) */
  subjectDid: string;
  /** Enrollment time (ISO 8601 format) */
  enrollmentTime?: string;
  privateJwk: string;
  /** Hours until expiration (default: 24). Use negative for expired JWTs. */
  expiresInHours?: number;
  /** Key ID to include in JWT header (for DID resolution) */
  kid?: string;
}

/**
 * Generate an Ed25519 keypair for testing.
 * Returns JWK strings matching the WASM generate_keypair() output format.
 */
export async function generateTestKeypair(): Promise<TestKeyPair> {
  const { privateKey, publicKey } = await jose.generateKeyPair('EdDSA', {
    crv: 'Ed25519',
    extractable: true,
  });

  const privateJwk = await jose.exportJWK(privateKey);
  const publicJwk = await jose.exportJWK(publicKey);

  return {
    privateJwk: JSON.stringify(privateJwk),
    publicJwk: JSON.stringify(publicJwk),
  };
}

/**
 * Issue a W3C-compliant JWT-VC matching backend SSI structure.
 */
export async function issueTestJwt(options: IssueJwtOptions): Promise<string> {
  const {
    issuerDid,
    subjectDid,
    enrollmentTime = new Date().toISOString(),
    privateJwk,
    expiresInHours = 24,
    kid,
  } = options;

  const jwk = JSON.parse(privateJwk) as jose.JWK;
  const privateKey = await jose.importJWK(jwk, 'EdDSA');

  const now = Math.floor(Date.now() / 1000);
  const exp = now + expiresInHours * 3600;

  // Build W3C VC structure matching backend SSI output
  const credentialSubject: CredentialSubject = {
    id: subjectDid,
    enrollmentTime: enrollmentTime,
  };

  const vc: VerifiableCredential = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    issuer: { id: issuerDid },
    issuanceDate: enrollmentTime,
    credentialSubject: credentialSubject,
  };

  // JWT claims with nested VC (W3C JWT-VC format)
  const builder = new jose.SignJWT({
    vc,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', ...(kid ? { kid } : {}) })
    .setSubject(subjectDid)
    .setIssuedAt(now)
    .setExpirationTime(exp);

  return builder.sign(privateKey);
}

/**
 * Generate a DID document for testing.
 * Uses camelCase field names matching W3C spec and backend.
 */
export function generateTestDidDocument(
  did: string,
  publicJwk: string,
  keyId: string = 'key-1',
): DidDocument {
  const publicKey = JSON.parse(publicJwk) as JsonWebKey;
  const fullKeyId = `${did}#${keyId}`;

  return {
    id: did,
    verificationMethod: [
      {
        id: fullKeyId,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: publicKey,
      },
    ],
    authentication: [fullKeyId],
  };
}

/**
 * Create a complete test fixture with keypair, DID document, and JWT.
 */
export async function createTestFixture(options?: {
  did?: string;
  subjectDid?: string;
  enrollmentTime?: string;
  keyId?: string;
  expiresInHours?: number;
}) {
  const {
    did = 'did:web:test.example',
    subjectDid = 'did:pkh:eip155:1:0x1234567890abcdef',
    enrollmentTime = new Date().toISOString(),
    keyId = 'key-1',
    expiresInHours = 24,
  } = options ?? {};

  const keypair = await generateTestKeypair();
  const didDocument = generateTestDidDocument(did, keypair.publicJwk, keyId);

  const jwt = await issueTestJwt({
    issuerDid: did,
    subjectDid,
    enrollmentTime,
    privateJwk: keypair.privateJwk,
    expiresInHours,
    kid: `${did}#${keyId}`,
  });

  return {
    keypair,
    didDocument,
    jwt,
    did,
    subjectDid,
    enrollmentTime,
  };
}
