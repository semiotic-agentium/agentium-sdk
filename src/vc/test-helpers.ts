// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

/**
 * Test helpers for VC integration tests.
 * Uses jose library for Ed25519 JWT signing.
 */

import * as jose from 'jose';
import type { DidDocument, MembershipClaims, JsonWebKey } from './types.js';

/**
 * Test keypair with JWK strings (matching WASM output format).
 */
export interface TestKeyPair {
  privateJwk: string;
  publicJwk: string;
}

/**
 * Options for issuing a test JWT.
 */
export interface IssueJwtOptions {
  issuer: string;
  subject: string;
  memberId: string;
  status: string;
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
 * Issue a test JWT-VC with membership claims.
 */
export async function issueTestJwt(options: IssueJwtOptions): Promise<string> {
  const { issuer, subject, memberId, status, privateJwk, expiresInHours = 24, kid } = options;

  const jwk = JSON.parse(privateJwk) as jose.JWK;
  const privateKey = await jose.importJWK(jwk, 'EdDSA');

  const now = Math.floor(Date.now() / 1000);
  const exp = now + expiresInHours * 3600;

  const membership: MembershipClaims = {
    member_id: memberId,
    status: status,
  };

  let builder = new jose.SignJWT({
    membership,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', ...(kid ? { kid } : {}) })
    .setIssuer(issuer)
    .setSubject(subject)
    .setIssuedAt(now)
    .setExpirationTime(exp);

  return builder.sign(privateKey);
}

/**
 * Generate a DID document for testing.
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
    verification_method: [
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
  subject?: string;
  memberId?: string;
  status?: string;
  keyId?: string;
  expiresInHours?: number;
}) {
  const {
    did = 'did:web:test.example',
    subject = 'user-123',
    memberId = 'member-456',
    status = 'active',
    keyId = 'key-1',
    expiresInHours = 24,
  } = options ?? {};

  const keypair = await generateTestKeypair();
  const didDocument = generateTestDidDocument(did, keypair.publicJwk, keyId);

  const jwt = await issueTestJwt({
    issuer: did,
    subject,
    memberId,
    status,
    privateJwk: keypair.privateJwk,
    expiresInHours,
    kid: `${did}#${keyId}`,
  });

  return {
    keypair,
    didDocument,
    jwt,
    did,
    subject,
    memberId,
    status,
  };
}
