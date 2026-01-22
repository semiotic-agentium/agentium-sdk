// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import { describe, it, expect, beforeAll, afterEach, afterAll, vi } from 'vitest';
import { AgentiumClient, AgentiumApiError, Caip2, Caip2Error } from './index';
import type { OAuthTokenResponse, WalletChallengeResponse, MessageSigner } from './index';
import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';

const BASE_URL = 'https://api.agentium.network';
const WALLET_CHALLENGE_PATH = '/auth/wallet/challenge';
const WALLET_VERIFY_PATH = '/auth/wallet/verify';

function createMockChallengeResponse(): WalletChallengeResponse {
  return {
    message:
      'payments-hub.agentium.ai wants you to sign in with your Ethereum account:\n0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7\n\nSign in to Agentium\n\nURI: https://payments-hub.agentium.ai\nVersion: 1\nChain ID: 8453\nNonce: abc123def456\nIssued At: 2025-01-21T12:00:00Z',
    nonce: 'abc123def456',
  };
}

function createMockOAuthResponse(options: {
  did?: string;
  isNew?: boolean;
}): OAuthTokenResponse {
  const did = options.did || 'did:pkh:eip155:8453:0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7';
  const isNew = options.isNew ?? false;
  const scope = `user ${did}${isNew ? ' new_user' : ''}`;

  return {
    access_token: 'mock-access-token',
    refresh_token: 'mock-refresh-token',
    token_type: 'Bearer',
    expires_in: 3600,
    scope,
  };
}

describe('Wallet Authentication', () => {
  let mock: MockAdapter;

  beforeAll(() => {
    mock = new MockAdapter(axios);
  });

  afterEach(() => {
    mock.reset();
  });

  afterAll(() => {
    mock.restore();
  });

  describe('requestWalletChallenge', () => {
    it('should request challenge with Base Mainnet by default', async () => {
      const client = new AgentiumClient();
      const address = '0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7';
      const mockChallenge = createMockChallengeResponse();

      mock
        .onGet(`${BASE_URL}${WALLET_CHALLENGE_PATH}?address=${address}&chain_id=eip155%3A8453`)
        .reply(200, mockChallenge);

      const response = await client.requestWalletChallenge(address);

      expect(response.message).toBe(mockChallenge.message);
      expect(response.nonce).toBe('abc123def456');
    });

    it('should request challenge with specified chain', async () => {
      const client = new AgentiumClient();
      const address = '0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7';
      const mockChallenge = createMockChallengeResponse();

      mock
        .onGet(`${BASE_URL}${WALLET_CHALLENGE_PATH}?address=${address}&chain_id=eip155%3A84532`)
        .reply(200, mockChallenge);

      const response = await client.requestWalletChallenge(address, Caip2.BASE_SEPOLIA);

      expect(response.message).toBeDefined();
      expect(response.nonce).toBeDefined();
    });

    it('should throw Caip2Error for unsupported chain', async () => {
      const client = new AgentiumClient();
      const address = '0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7';
      const ethereumMainnet = Caip2.parse('eip155:1');

      await expect(client.requestWalletChallenge(address, ethereumMainnet)).rejects.toThrow(
        Caip2Error,
      );
      await expect(client.requestWalletChallenge(address, ethereumMainnet)).rejects.toThrow(
        'Unsupported chain',
      );
    });

    it('should handle API errors gracefully', async () => {
      const client = new AgentiumClient();
      const address = '0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7';

      mock
        .onGet(new RegExp(`${WALLET_CHALLENGE_PATH}`))
        .reply(400, { message: 'Invalid address format' });

      await expect(client.requestWalletChallenge(address)).rejects.toThrow(AgentiumApiError);
    });
  });

  describe('verifyWalletSignature', () => {
    it('should verify signature and return tokens', async () => {
      const client = new AgentiumClient();
      const message = createMockChallengeResponse().message;
      const signature = '0x1234567890abcdef';
      const mockResponse = createMockOAuthResponse({ isNew: true });

      mock.onPost(`${BASE_URL}${WALLET_VERIFY_PATH}`, { message, signature }).reply(200, mockResponse);

      const response = await client.verifyWalletSignature(message, signature);

      expect(response.access_token).toBe('mock-access-token');
      expect(response.refresh_token).toBe('mock-refresh-token');
      expect(response.token_type).toBe('Bearer');
      expect(response.expires_in).toBe(3600);
    });

    it('should handle invalid signature error', async () => {
      const client = new AgentiumClient();
      const message = 'some message';
      const signature = 'invalid-signature';

      mock.onPost(`${BASE_URL}${WALLET_VERIFY_PATH}`).reply(401, { message: 'Invalid signature' });

      await expect(client.verifyWalletSignature(message, signature)).rejects.toThrow(
        AgentiumApiError,
      );
      await expect(client.verifyWalletSignature(message, signature)).rejects.toMatchObject({
        statusCode: 401,
      });
    });
  });

  describe('connectWallet', () => {
    it('should complete full wallet sign-in flow', async () => {
      const client = new AgentiumClient();
      const address = '0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7';
      const mockChallenge = createMockChallengeResponse();
      const mockSignature = '0xsignature123';
      const mockOAuthResponse = createMockOAuthResponse({
        did: 'did:pkh:eip155:8453:0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7',
        isNew: true,
      });

      // Mock signer function
      const mockSigner: MessageSigner = vi.fn().mockResolvedValue(mockSignature);

      // Mock challenge request
      mock
        .onGet(`${BASE_URL}${WALLET_CHALLENGE_PATH}?address=${address}&chain_id=eip155%3A8453`)
        .reply(200, mockChallenge);

      // Mock verify request
      mock
        .onPost(`${BASE_URL}${WALLET_VERIFY_PATH}`, {
          message: mockChallenge.message,
          signature: mockSignature,
        })
        .reply(200, mockOAuthResponse);

      const response = await client.connectWallet(address, Caip2.BASE_MAINNET, mockSigner);

      expect(mockSigner).toHaveBeenCalledWith(mockChallenge.message);
      expect(response.did).toBe('did:pkh:eip155:8453:0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7');
      expect(response.isNew).toBe(true);
      expect(response.badge.status).toBe('Active');
      expect(response.accessToken).toBe('mock-access-token');
      expect(response.refreshToken).toBe('mock-refresh-token');
      expect(response.expiresIn).toBe(3600);
    });
   

    it('should propagate signer errors', async () => {
      const client = new AgentiumClient();
      const address = '0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7';
      const mockChallenge = createMockChallengeResponse();

      const mockSigner: MessageSigner = vi.fn().mockRejectedValue(new Error('User rejected'));

      mock
        .onGet(`${BASE_URL}${WALLET_CHALLENGE_PATH}?address=${address}&chain_id=eip155%3A8453`)
        .reply(200, mockChallenge);

      await expect(client.connectWallet(address, Caip2.BASE_MAINNET, mockSigner)).rejects.toThrow(
        'User rejected',
      );
    });

    it('should work with Base Sepolia testnet', async () => {
      const client = new AgentiumClient();
      const address = '0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7';
      const mockChallenge = createMockChallengeResponse();
      const mockSignature = '0xsignature123';
      const mockOAuthResponse = createMockOAuthResponse({
        did: 'did:pkh:eip155:84532:0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7',
        isNew: true,
      });

      const mockSigner: MessageSigner = vi.fn().mockResolvedValue(mockSignature);

      mock
        .onGet(`${BASE_URL}${WALLET_CHALLENGE_PATH}?address=${address}&chain_id=eip155%3A84532`)
        .reply(200, mockChallenge);

      mock.onPost(`${BASE_URL}${WALLET_VERIFY_PATH}`).reply(200, mockOAuthResponse);

      const response = await client.connectWallet(address, Caip2.BASE_SEPOLIA, mockSigner);

      expect(response.did).toBe('did:pkh:eip155:84532:0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7');
    });
  });

  describe('AgentiumClient wallet methods exist', () => {
    it('should have all wallet methods', () => {
      const client = new AgentiumClient();
      expect(client.requestWalletChallenge).toBeInstanceOf(Function);
      expect(client.verifyWalletSignature).toBeInstanceOf(Function);
      expect(client.connectWallet).toBeInstanceOf(Function);
    });
  });
});
