// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import axios, { isAxiosError, type AxiosInstance } from 'axios';

/**
 * Options for configuring the AgentiumClient.
 */
export interface AgentiumClientOptions {
  /**
   * The base URL of the Agentium API.
   * @default https://api.agentium.network
   */
  baseURL?: string;
}

/**
 * Supported OAuth grant types for token exchange.
 */
export type GrantType =
  | 'api_key'
  | 'refresh_token'
  | 'privy_id_token'
  | 'google_id_token'
  | 'external_google';

/**
 * OAuth 2.0 token response from the backend.
 */
export interface OAuthTokenResponse {
  /**
   * JWT access token for authenticated API calls.
   */
  access_token: string;
  /**
   * JWT refresh token for obtaining new access tokens.
   */
  refresh_token: string;
  /**
   * Token type (always "Bearer").
   */
  token_type: string;
  /**
   * Token expiration time in seconds.
   */
  expires_in: number;
  /**
   * Space-separated scope string containing user info and DID.
   * Format: "user did:pkh:eip155:1:0x... [new_user]"
   */
  scope: string;
}

/**
 * Represents the status of a user's badge.
 */
export interface Badge {
  status: string;
}

/**
 * The response payload from a successful connect identity call.
 * Extends OAuth token response with parsed identity information.
 */
export interface ConnectIdentityResponse {
  /**
   * The user's Decentralized Identifier (DID).
   */
  did: string;
  /**
   * Information about the user's badge status.
   */
  badge: Badge;
  /**
   * Whether this is a newly created identity.
   */
  isNew: boolean;
  /**
   * JWT access token for authenticated API calls.
   */
  accessToken: string;
  /**
   * JWT refresh token for obtaining new access tokens.
   */
  refreshToken: string;
  /**
   * Token expiration time in seconds.
   */
  expiresIn: number;
}

/**
 * Options for connecting a Google identity.
 */
export interface ConnectGoogleIdentityOptions {
  /**
   * Skip audience validation for the Google token.
   * Set to `true` when using tokens from external OAuth clients (e.g., zkLogin)
   * that have a different Google Client ID than the backend.
   * @default false
   */
  skipAudienceValidation?: boolean;
}

/**
 * Custom error class for API-related errors from the AgentiumClient.
 */
export class AgentiumApiError extends Error {
  public readonly statusCode: number | undefined;

  constructor(message: string, statusCode?: number) {
    super(message);
    this.name = 'AgentiumApiError';
    this.statusCode = statusCode;
  }
}

/**
 * Parses the OAuth scope string to extract the DID and new_user flag.
 * Scope format: "user did:pkh:eip155:1:0x... [new_user]"
 */
function parseScopeForIdentity(scope: string): { did: string; isNew: boolean } {
  const parts = scope.split(/\s+/);
  const did = parts.find((part) => part.startsWith('did:pkh:')) || '';
  const isNew = parts.includes('new_user');
  return { did, isNew };
}

/**
 * A client for interacting with the Agentium API.
 */
export class AgentiumClient {
  private readonly axiosInstance: AxiosInstance;
  private readonly DEFAULT_BASE_URL = 'https://api.agentium.network';
  private readonly OAUTH_TOKEN_PATH = '/oauth/token';

  /**
   * Creates an instance of the AgentiumClient.
   * @param options - Configuration options for the client.
   */
  constructor(options: AgentiumClientOptions = {}) {
    const baseURL = options.baseURL || this.DEFAULT_BASE_URL;
    this.axiosInstance = axios.create({
      baseURL: baseURL,
    });
  }

  /**
   * Connects a Google identity to an Agentium identity.
   * @param googleToken - The JWT token obtained from Google Sign-In.
   * @param options - Optional configuration for the connection.
   * @returns A promise that resolves with the connection response, containing the user's DID and tokens.
   * @throws {AgentiumApiError} Will throw a custom API error if the call fails.
   *  - **400 (Bad Request):** The request was malformed or unsupported grant type.
   *  - **401 (Unauthorized):** The provided JWT token is invalid or expired.
   *  - **500 (Internal Server Error):** An unexpected error occurred on the server.
   */
  async connectGoogleIdentity(
    googleToken: string,
    options: ConnectGoogleIdentityOptions = {},
  ): Promise<ConnectIdentityResponse> {
    const grantType: GrantType = options.skipAudienceValidation
      ? 'external_google'
      : 'google_id_token';

    try {
      const response = await this.axiosInstance.post<OAuthTokenResponse>(this.OAUTH_TOKEN_PATH, {
        grant_type: grantType,
        id_token: googleToken,
      });

      const { did, isNew } = parseScopeForIdentity(response.data.scope);

      return {
        did,
        badge: { status: isNew ? 'Active' : 'Existing' },
        isNew,
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        expiresIn: response.data.expires_in,
      };
    } catch (error) {
      if (isAxiosError(error)) {
        throw new AgentiumApiError(error.message, error.response?.status);
      }
      throw error;
    }
  }

  /**
   * Exchanges an API key for JWT tokens (M2M authentication).
   * @param apiKey - The API key to exchange.
   * @returns A promise that resolves with the OAuth token response.
   * @throws {AgentiumApiError} Will throw a custom API error if the call fails.
   */
  async exchangeApiKey(apiKey: string): Promise<OAuthTokenResponse> {
    try {
      const response = await this.axiosInstance.post<OAuthTokenResponse>(this.OAUTH_TOKEN_PATH, {
        grant_type: 'api_key' as GrantType,
        api_key: apiKey,
      });
      return response.data;
    } catch (error) {
      if (isAxiosError(error)) {
        throw new AgentiumApiError(error.message, error.response?.status);
      }
      throw error;
    }
  }

  /**
   * Refreshes an access token using a refresh token.
   * @param refreshTokenValue - The refresh token to use.
   * @returns A promise that resolves with the new OAuth token response.
   * @throws {AgentiumApiError} Will throw a custom API error if the call fails.
   */
  async refreshToken(refreshTokenValue: string): Promise<OAuthTokenResponse> {
    try {
      const response = await this.axiosInstance.post<OAuthTokenResponse>(this.OAUTH_TOKEN_PATH, {
        grant_type: 'refresh_token' as GrantType,
        refresh_token: refreshTokenValue,
      });
      return response.data;
    } catch (error) {
      if (isAxiosError(error)) {
        throw new AgentiumApiError(error.message, error.response?.status);
      }
      throw error;
    }
  }

  /**
   * Exchanges a Privy ID token for JWT tokens.
   * @param idToken - The Privy ID token to exchange.
   * @returns A promise that resolves with the OAuth token response.
   * @throws {AgentiumApiError} Will throw a custom API error if the call fails.
   */
  async exchangePrivyToken(idToken: string): Promise<OAuthTokenResponse> {
    try {
      const response = await this.axiosInstance.post<OAuthTokenResponse>(this.OAUTH_TOKEN_PATH, {
        grant_type: 'privy_id_token' as GrantType,
        id_token: idToken,
      });
      return response.data;
    } catch (error) {
      if (isAxiosError(error)) {
        throw new AgentiumApiError(error.message, error.response?.status);
      }
      throw error;
    }
  }
}
