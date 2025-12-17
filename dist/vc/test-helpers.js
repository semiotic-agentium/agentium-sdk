// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT
/**
 * Test helpers for VC integration tests.
 * Uses jose library for Ed25519 JWT signing.
 * Generates W3C-compliant VCs matching backend SSI implementation.
 */
import * as jose from 'jose';
/**
 * Generate an Ed25519 keypair for testing.
 * Returns JWK strings matching the WASM generate_keypair() output format.
 */
export async function generateTestKeypair() {
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
export async function issueTestJwt(options) {
    const { issuerDid, subjectDid, enrollmentTime = new Date().toISOString(), privateJwk, expiresInHours = 24, kid, } = options;
    const jwk = JSON.parse(privateJwk);
    const privateKey = await jose.importJWK(jwk, 'EdDSA');
    const now = Math.floor(Date.now() / 1000);
    const exp = now + expiresInHours * 3600;
    // Build W3C VC structure matching backend SSI output
    const credentialSubject = {
        id: subjectDid,
        enrollmentTime: enrollmentTime,
    };
    const vc = {
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
export function generateTestDidDocument(did, publicJwk, keyId = 'key-1') {
    const publicKey = JSON.parse(publicJwk);
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
export async function createTestFixture(options) {
    const { did = 'did:web:test.example', subjectDid = 'did:pkh:eip155:1:0x1234567890abcdef', enrollmentTime = new Date().toISOString(), keyId = 'key-1', expiresInHours = 24, } = options ?? {};
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
//# sourceMappingURL=test-helpers.js.map