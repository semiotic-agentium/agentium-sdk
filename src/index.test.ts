// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import { AgentiumClient, AgentiumApiError, type OAuthTokenResponse } from './index';
import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';

/**
 * Helper to create a mock OAuth token response.
 */
function createMockOAuthResponse(options: {
  did?: string;
  isNew?: boolean;
  scope?: string;
}): OAuthTokenResponse {
  const did = options.did || 'did:pkh:eip155:1:0x1234567890abcdef';
  const isNew = options.isNew ?? false;
  const scope = options.scope || `user ${did}${isNew ? ' new_user' : ''}`;

  return {
    access_token: 'mock-access-token',
    refresh_token: 'mock-refresh-token',
    token_type: 'Bearer',
    expires_in: 3600,
    scope,
  };
}

describe('AgentiumClient', () => {
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

  it('should be defined', () => {
    expect(AgentiumClient).toBeDefined();
  });

  it('should have all expected methods', () => {
    const client = new AgentiumClient();
    expect(client.connectGoogleIdentity).toBeInstanceOf(Function);
    expect(client.exchangeApiKey).toBeInstanceOf(Function);
    expect(client.refreshToken).toBeInstanceOf(Function);
    expect(client.exchangePrivyToken).toBeInstanceOf(Function);
  });

  it('should accept a baseURL in the constructor and use default if not provided', () => {
    const axiosCreateSpy = vi.spyOn(axios, 'create');

    new AgentiumClient();
    expect(axiosCreateSpy).toHaveBeenCalledWith({
      baseURL: 'https://api.agentium.network',
    });
    axiosCreateSpy.mockClear();

    const customURL = 'http://localhost:3000';
    new AgentiumClient({ baseURL: customURL });
    expect(axiosCreateSpy).toHaveBeenCalledWith({
      baseURL: customURL,
    });
    axiosCreateSpy.mockRestore();
  });

  describe('connectGoogleIdentity', () => {
    it('should use google_id_token grant type by default', async () => {
      const client = new AgentiumClient();
      const googleToken = 'test-google-jwt';
      const mockResponse = createMockOAuthResponse({
        did: 'did:pkh:eip155:1:0xabcdef',
        isNew: true,
      });

      mock
        .onPost('https://api.agentium.network/oauth/token', {
          grant_type: 'google_id_token',
          id_token: googleToken,
        })
        .reply(200, mockResponse);

      const response = await client.connectGoogleIdentity(googleToken);

      expect(response.did).toBe('did:pkh:eip155:1:0xabcdef');
      expect(response.isNew).toBe(true);
      expect(response.badge.status).toBe('Active');
      expect(response.accessToken).toBe('mock-access-token');
      expect(response.refreshToken).toBe('mock-refresh-token');
      expect(response.expiresIn).toBe(3600);
    });

    it('should use external_google grant type when skipAudienceValidation is true', async () => {
      const client = new AgentiumClient();
      const googleToken = 'test-zklogin-jwt';
      const mockResponse = createMockOAuthResponse({
        did: 'did:pkh:eip155:1:0xzklogin',
        isNew: false,
      });

      mock
        .onPost('https://api.agentium.network/oauth/token', {
          grant_type: 'external_google',
          id_token: googleToken,
        })
        .reply(200, mockResponse);

      const response = await client.connectGoogleIdentity(googleToken, {
        skipAudienceValidation: true,
      });

      expect(response.did).toBe('did:pkh:eip155:1:0xzklogin');
      expect(response.isNew).toBe(false);
      expect(response.badge.status).toBe('Existing');
    });

    it('should work with custom baseURL', async () => {
      const customBaseURL = 'http://localhost:8080';
      const client = new AgentiumClient({ baseURL: customBaseURL });
      const googleToken = 'test-custom-google-jwt';
      const mockResponse = createMockOAuthResponse({ did: 'did:pkh:eip155:1:0xcustom' });

      mock
        .onPost(`${customBaseURL}/oauth/token`, {
          grant_type: 'google_id_token',
          id_token: googleToken,
        })
        .reply(200, mockResponse);

      const response = await client.connectGoogleIdentity(googleToken);
      expect(response.did).toBe('did:pkh:eip155:1:0xcustom');
    });

    it('should handle API errors gracefully', async () => {
      const client = new AgentiumClient();
      const googleToken = 'invalid-token';

      mock
        .onPost('https://api.agentium.network/oauth/token')
        .reply(401, { message: 'Unauthorized' });

      await expect(client.connectGoogleIdentity(googleToken)).rejects.toThrow(AgentiumApiError);
      await expect(client.connectGoogleIdentity(googleToken)).rejects.toMatchObject({
        name: 'AgentiumApiError',
        statusCode: 401,
      });
    });
  });

  describe('exchangeApiKey', () => {
    it('should exchange API key for tokens', async () => {
      const client = new AgentiumClient();
      const apiKey = 'ak_test123';
      const mockResponse = createMockOAuthResponse({});

      mock
        .onPost('https://api.agentium.network/oauth/token', {
          grant_type: 'api_key',
          api_key: apiKey,
        })
        .reply(200, mockResponse);

      const response = await client.exchangeApiKey(apiKey);

      expect(response.access_token).toBe('mock-access-token');
      expect(response.refresh_token).toBe('mock-refresh-token');
      expect(response.token_type).toBe('Bearer');
      expect(response.expires_in).toBe(3600);
    });

    it('should handle invalid API key error', async () => {
      const client = new AgentiumClient();
      const apiKey = 'invalid-key';

      mock
        .onPost('https://api.agentium.network/oauth/token')
        .reply(401, { message: 'Invalid API key' });

      await expect(client.exchangeApiKey(apiKey)).rejects.toThrow(AgentiumApiError);
      await expect(client.exchangeApiKey(apiKey)).rejects.toMatchObject({
        statusCode: 401,
      });
    });
  });

  describe('refreshToken', () => {
    it('should refresh access token', async () => {
      const client = new AgentiumClient();
      const refreshTokenValue = 'mock-refresh-token';
      const mockResponse: OAuthTokenResponse = {
        access_token: 'new-access-token',
        refresh_token: refreshTokenValue,
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'user',
      };

      mock
        .onPost('https://api.agentium.network/oauth/token', {
          grant_type: 'refresh_token',
          refresh_token: refreshTokenValue,
        })
        .reply(200, mockResponse);

      const response = await client.refreshToken(refreshTokenValue);

      expect(response.access_token).toBe('new-access-token');
      expect(response.refresh_token).toBe(refreshTokenValue);
    });

    it('should handle invalid refresh token error', async () => {
      const client = new AgentiumClient();

      mock
        .onPost('https://api.agentium.network/oauth/token')
        .reply(401, { message: 'Invalid token' });

      await expect(client.refreshToken('invalid-refresh-token')).rejects.toThrow(AgentiumApiError);
    });
  });

  describe('exchangePrivyToken', () => {
    it('should exchange Privy token for JWT tokens', async () => {
      const client = new AgentiumClient();
      const privyToken = 'privy-id-token';
      const mockResponse = createMockOAuthResponse({});

      mock
        .onPost('https://api.agentium.network/oauth/token', {
          grant_type: 'privy_id_token',
          id_token: privyToken,
        })
        .reply(200, mockResponse);

      const response = await client.exchangePrivyToken(privyToken);

      expect(response.access_token).toBe('mock-access-token');
      expect(response.token_type).toBe('Bearer');
    });

    it('should handle invalid Privy token error', async () => {
      const client = new AgentiumClient();

      mock
        .onPost('https://api.agentium.network/oauth/token')
        .reply(401, { message: 'Invalid Privy token' });

      await expect(client.exchangePrivyToken('invalid-privy-token')).rejects.toThrow(
        AgentiumApiError,
      );
    });
  });
});
