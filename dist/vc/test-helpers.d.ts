import type { DidDocument } from './types.js';
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
export declare function generateTestKeypair(): Promise<TestKeyPair>;
/**
 * Issue a W3C-compliant JWT-VC matching backend SSI structure.
 */
export declare function issueTestJwt(options: IssueJwtOptions): Promise<string>;
/**
 * Generate a DID document for testing.
 * Uses camelCase field names matching W3C spec and backend.
 */
export declare function generateTestDidDocument(did: string, publicJwk: string, keyId?: string): DidDocument;
/**
 * Create a complete test fixture with keypair, DID document, and JWT.
 */
export declare function createTestFixture(options?: {
    did?: string;
    subjectDid?: string;
    enrollmentTime?: string;
    keyId?: string;
    expiresInHours?: number;
}): Promise<{
    keypair: TestKeyPair;
    didDocument: DidDocument;
    jwt: string;
    did: string;
    subjectDid: string;
    enrollmentTime: string;
}>;
//# sourceMappingURL=test-helpers.d.ts.map