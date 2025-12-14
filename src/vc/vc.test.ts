// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';
import { AgentiumClient, AgentiumApiError } from '../index.js';
import { verifyJwt } from '../wasm.js';
import { createMemoryStorage } from './storage.js';
import { createTestFixture, generateTestKeypair, generateTestDidDocument } from './test-helpers.js';

describe('VC Module', () => {
  let mock: MockAdapter;

  // WASM is initialized in vitest.setup.ts via initSync()

  beforeEach(() => {
    mock = new MockAdapter(axios);
  });

  afterEach(() => {
    mock.reset();
    mock.restore();
  });

  describe('WASM verifyJwt', () => {
    it('should verify a valid JWT signed with Ed25519', async () => {
      const fixture = await createTestFixture();

      const result = await verifyJwt(fixture.jwt, fixture.keypair.publicJwk, false);

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
      expect(result.claims).toBeDefined();
      expect(result.claims?.vc.issuer.id).toBe(fixture.did);
      expect(result.claims?.sub).toBe(fixture.subjectDid);
      expect(result.claims?.vc.credentialSubject.id).toBe(fixture.subjectDid);
      expect(result.claims?.vc.credentialSubject.enrollmentTime).toBe(fixture.enrollmentTime);
    });

    it('should reject JWT signed with wrong key', async () => {
      const fixture = await createTestFixture();
      const wrongKeypair = await generateTestKeypair();

      const result = await verifyJwt(fixture.jwt, wrongKeypair.publicJwk, false);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('VERIFICATION_FAILED');
      expect(result.error?.message).toContain('Signature verification failed');
    });

    it('should reject expired JWT when expiration check is enabled', async () => {
      const fixture = await createTestFixture({ expiresInHours: -1 }); // Already expired

      const result = await verifyJwt(fixture.jwt, fixture.keypair.publicJwk, true);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('JWT_EXPIRED');
      expect(result.error?.message).toContain('expired');
    });

    it('should accept expired JWT when expiration check is disabled', async () => {
      const fixture = await createTestFixture({ expiresInHours: -1 });

      const result = await verifyJwt(fixture.jwt, fixture.keypair.publicJwk, false);

      expect(result.valid).toBe(true);
    });

    it('should reject malformed JWT', async () => {
      const fixture = await createTestFixture();

      const result = await verifyJwt('not.a.valid.jwt.format', fixture.keypair.publicJwk, false);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('INVALID_JWT_FORMAT');
    });

    it('should reject JWT with invalid base64 encoding', async () => {
      const fixture = await createTestFixture();

      const result = await verifyJwt('invalid!!!.base64.here', fixture.keypair.publicJwk, false);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('AgentiumClient.parseJwtHeader', () => {
    it('should extract header from valid JWT', async () => {
      const client = new AgentiumClient();
      const fixture = await createTestFixture({ keyId: 'my-key-id' });

      const header = client.parseJwtHeader(fixture.jwt);

      expect(header.alg).toBe('EdDSA');
      expect(header.typ).toBe('JWT');
      expect(header.kid).toBe(`${fixture.did}#my-key-id`);
    });

    it('should throw on invalid JWT format', () => {
      const client = new AgentiumClient();

      expect(() => client.parseJwtHeader('not-a-jwt')).toThrow(AgentiumApiError);
      expect(() => client.parseJwtHeader('only.two')).toThrow('expected 3 parts');
    });
  });

  describe('AgentiumClient.extractPublicKeyJwk', () => {
    it('should extract public key from DID document', async () => {
      const client = new AgentiumClient();
      const keypair = await generateTestKeypair();
      const didDoc = generateTestDidDocument('did:web:example.com', keypair.publicJwk, 'key-1');

      const publicKeyJwk = client.extractPublicKeyJwk(didDoc);

      expect(publicKeyJwk).toBe(keypair.publicJwk);
    });

    it('should find key by kid', async () => {
      const client = new AgentiumClient();
      const keypair = await generateTestKeypair();
      const didDoc = generateTestDidDocument(
        'did:web:example.com',
        keypair.publicJwk,
        'specific-key',
      );

      const publicKeyJwk = client.extractPublicKeyJwk(didDoc, 'did:web:example.com#specific-key');

      expect(publicKeyJwk).toBe(keypair.publicJwk);
    });

    it('should find key by fragment only', async () => {
      const client = new AgentiumClient();
      const keypair = await generateTestKeypair();
      const didDoc = generateTestDidDocument('did:web:example.com', keypair.publicJwk, 'key-1');

      const publicKeyJwk = client.extractPublicKeyJwk(didDoc, 'key-1');

      expect(publicKeyJwk).toBe(keypair.publicJwk);
    });

    it('should throw when no verification methods exist', () => {
      const client = new AgentiumClient();
      const emptyDidDoc = { id: 'did:web:example.com', verificationMethod: [] };

      expect(() => client.extractPublicKeyJwk(emptyDidDoc)).toThrow(AgentiumApiError);
    });
  });

  describe('AgentiumClient.verifyCredential', () => {
    it('should verify credential with full flow (fetch DID doc, extract key, verify)', async () => {
      const client = new AgentiumClient();
      const fixture = await createTestFixture({
        did: 'did:web:api.agentium.network',
        keyId: 'key-1',
      });

      // Mock the DID document endpoint
      mock
        .onGet('https://api.agentium.network/.well-known/did.json')
        .reply(200, fixture.didDocument);

      const result = await client.verifyCredential(fixture.jwt, false);

      expect(result.valid).toBe(true);
      expect(result.claims?.vc.issuer.id).toBe('did:web:api.agentium.network');
    });

    it('should handle DID document fetch failure', async () => {
      const client = new AgentiumClient();
      const fixture = await createTestFixture();

      mock.onGet('https://api.agentium.network/.well-known/did.json').reply(500);

      await expect(client.verifyCredential(fixture.jwt)).rejects.toThrow(AgentiumApiError);
    });

    it('should fail verification when DID doc has wrong key', async () => {
      const client = new AgentiumClient();
      const fixture = await createTestFixture({ did: 'did:web:api.agentium.network' });
      const wrongKeypair = await generateTestKeypair();
      const wrongDidDoc = generateTestDidDocument(
        'did:web:api.agentium.network',
        wrongKeypair.publicJwk,
        'key-1',
      );

      mock.onGet('https://api.agentium.network/.well-known/did.json').reply(200, wrongDidDoc);

      const result = await client.verifyCredential(fixture.jwt, false);

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('VERIFICATION_FAILED');
      expect(result.error?.message).toContain('Signature verification failed');
    });
  });

  describe('AgentiumClient.connectAndStoreMembership', () => {
    it('should fetch, verify, and store valid credential', async () => {
      const client = new AgentiumClient();
      const storage = createMemoryStorage();
      client.setVcStorage(storage);

      const fixture = await createTestFixture({
        did: 'did:web:api.agentium.network',
        keyId: 'key-1',
      });

      // Mock credential fetch endpoint
      mock
        .onPost('https://api.agentium.network/v1/credentials/membership')
        .reply(200, { vc: fixture.jwt });

      // Mock DID document endpoint
      mock
        .onGet('https://api.agentium.network/.well-known/did.json')
        .reply(200, fixture.didDocument);

      const result = await client.connectAndStoreMembership('fake-privy-token');

      expect(result.valid).toBe(true);
      expect(storage.get()).toBe(fixture.jwt);
    });

    it('should not store invalid credential', async () => {
      const client = new AgentiumClient();
      const storage = createMemoryStorage();
      client.setVcStorage(storage);

      const fixture = await createTestFixture({ did: 'did:web:api.agentium.network' });
      const wrongKeypair = await generateTestKeypair();
      const wrongDidDoc = generateTestDidDocument(
        'did:web:api.agentium.network',
        wrongKeypair.publicJwk,
      );

      mock
        .onPost('https://api.agentium.network/v1/credentials/membership')
        .reply(200, { vc: fixture.jwt });
      mock.onGet('https://api.agentium.network/.well-known/did.json').reply(200, wrongDidDoc);

      const result = await client.connectAndStoreMembership('fake-privy-token');

      expect(result.valid).toBe(false);
      expect(storage.get()).toBeNull();
    });

    it('should handle fetch errors silently (return invalid result)', async () => {
      const client = new AgentiumClient();

      mock.onPost('https://api.agentium.network/v1/credentials/membership').reply(401);

      const result = await client.connectAndStoreMembership('invalid-token');

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should retrieve stored credential', async () => {
      const client = new AgentiumClient();
      const storage = createMemoryStorage();
      client.setVcStorage(storage);

      const fixture = await createTestFixture();
      storage.set(fixture.jwt);

      expect(client.getStoredCredential()).toBe(fixture.jwt);
    });
  });

  describe('AgentiumClient.fetchIssuerDidDocument', () => {
    it('should fetch DID document from well-known endpoint', async () => {
      const client = new AgentiumClient();
      const keypair = await generateTestKeypair();
      const didDoc = generateTestDidDocument('did:web:api.agentium.network', keypair.publicJwk);

      mock.onGet('https://api.agentium.network/.well-known/did.json').reply(200, didDoc);

      const result = await client.fetchIssuerDidDocument();

      expect(result.id).toBe('did:web:api.agentium.network');
      expect(result.verificationMethod).toHaveLength(1);
    });

    it('should throw on fetch failure', async () => {
      const client = new AgentiumClient();

      mock.onGet('https://api.agentium.network/.well-known/did.json').reply(404);

      await expect(client.fetchIssuerDidDocument()).rejects.toThrow(AgentiumApiError);
    });
  });
});
