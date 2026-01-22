// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import axios, { isAxiosError, type AxiosInstance } from 'axios';
import { ensureWasmReady, verifyJwt, type WasmInitInput } from './wasm.js';
import {
  parse_jwt_header as wasmParseJwtHeader,
  extract_public_key_jwk as wasmExtractPublicKeyJwk,
} from '../packages/agentium-native/wasm/pkg/agentium_sdk_wasm.js';
import type { VcStorage, VerificationResult, DidDocument, JwtHeader } from './vc/index.js';
import { Caip2, Caip2Error, assertSupportedChain } from './caip2.js';
import type { WalletChallengeResponse, MessageSigner } from './types/wallet.js';

// Re-export VC module types and utilities
export * from './vc/index.js';
export {
  ensureWasmReady,
  verifyJwt,
  generateKeypair,
  getPublicKey,
  parseJwtHeader,
  extractPublicKeyJwk,
  type WasmInitInput,
} from './wasm.js';

// Re-export telemetry module
export {
  initTelemetry,
  consoleSink,
  nullSink,
  withLevelFilter,
  withTargetFilter,
  composeSinks,
  type TelemetryEvent,
  type TelemetryLevel,
  type TelemetrySink,
  type InitTelemetryOptions,
} from './telemetry.js';

// Re-export CAIP-2 utilities
export { Caip2, Caip2Error, assertSupportedChain } from './caip2.js';

// Re-export wallet types
export type { WalletChallengeResponse, MessageSigner } from './types/wallet.js';

/**
 * Options for configuring the AgentiumClient.
 */
export interface AgentiumClientOptions {
  /**
   * The base URL of the Agentium API.
   * @default https://api.agentium.network
   */
  baseURL?: string;

  /**
   * URL to the WASM binary. Required for bundlers like Vite that need explicit URL resolution.
   * @example
   * ```typescript
   * import wasmUrl from '@semiotic-labs/agentium-sdk/wasm?url';
   * const client = new AgentiumClient({ wasmUrl });
   * ```
   */
  wasmUrl?: WasmInitInput;
}

/**
 * Options for initiating OIDC login.
 */
export interface OidcLoginOptions {
  /**
   * The URL where Google will redirect after authentication.
   * Must be registered in the backend's Google Cloud Console.
   * Must use http or https protocol.
   */
  redirectUri: string;
}

/**
 * Parameters received from the OIDC callback.
 */
export interface OidcCallbackParams {
  /**
   * Authorization code from Google.
   */
  code: string;
  /**
   * State token for CSRF validation.
   */
  state: string;
}

/**
 * Parsed permissions from the OAuth scope string.
 */
export interface ParsedPermissions {
  /**
   * Whether the user has base user permission.
   */
  isUser: boolean;
  /**
   * Whether this is a newly created user.
   */
  isNewUser: boolean;
  /**
   * The user's blockchain DID (did:pkh:...), if present.
   */
  did: string | null;
  /**
   * The user's profile ID, if present.
   */
  profileId: string | null;
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
  private readonly baseURL: string;
  private readonly DEFAULT_BASE_URL = 'https://api.agentium.network';
  private readonly OAUTH_TOKEN_PATH = '/oauth/token';
  private readonly OIDC_LOGIN_PATH = '/auth/oidc/login';
  private readonly OIDC_CALLBACK_PATH = '/auth/oidc/callback';
  private readonly WALLET_CHALLENGE_PATH = '/auth/wallet/challenge';
  private readonly WALLET_VERIFY_PATH = '/auth/wallet/verify';
  private readonly wasmReady: Promise<void>;
  private vcStorage: VcStorage | null = null;

  /**
   * Creates an instance of the AgentiumClient.
   * @param options - Configuration options for the client.
   */
  constructor(options: AgentiumClientOptions = {}) {
    this.baseURL = options.baseURL || this.DEFAULT_BASE_URL;
    this.axiosInstance = axios.create({
      baseURL: this.baseURL,
    });
    this.wasmReady = ensureWasmReady(options.wasmUrl);
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
   * Generates the OIDC login URL for redirecting users to Google authentication.
   * Use this when you need the URL without performing the redirect (e.g., for custom UI).
   *
   * @param options - Login options including the redirect URI
   * @returns The full URL to redirect the user to
   * @throws {Error} If redirect_uri is not http or https
   */
  getOidcLoginUrl(options: OidcLoginOptions): string {
    const url = new URL(options.redirectUri);
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new Error('redirect_uri must use http or https protocol');
    }
    return `${this.baseURL}${this.OIDC_LOGIN_PATH}?redirect_uri=${encodeURIComponent(options.redirectUri)}`;
  }

  /**
   * Initiates OIDC login by redirecting to the backend's login endpoint.
   * The backend will redirect to Google OAuth, and after authentication,
   * Google will redirect back to the specified redirect_uri with code and state parameters.
   *
   * Note: This method only works in browser environments.
   *
   * @param options - Login options including the redirect URI
   * @throws {Error} If redirect_uri is not http or https, or if not in a browser environment
   *
   * @example
   * ```typescript
   * // Redirect user to Google login
   * client.startOidcLogin({ redirectUri: 'https://myapp.com/auth/callback' });
   * ```
   */
  startOidcLogin(options: OidcLoginOptions): void {
    if (typeof window === 'undefined') {
      throw new Error('startOidcLogin can only be used in browser environments');
    }
    const loginUrl = this.getOidcLoginUrl(options);
    window.location.href = loginUrl;
  }

  /**
   * Exchanges the authorization code from the OIDC callback for tokens.
   * Call this after receiving the redirect from Google with code and state parameters.
   *
   * @param params - The code and state parameters from the callback URL
   * @returns OAuth token response with access_token, refresh_token, etc.
   * @throws {AgentiumApiError} If the exchange fails (invalid code, expired state, etc.)
   *
   * @example
   * ```typescript
   * // In your callback handler
   * const urlParams = new URLSearchParams(window.location.search);
   * const tokens = await client.exchangeOidcCode({
   *   code: urlParams.get('code')!,
   *   state: urlParams.get('state')!,
   * });
   * ```
   */
  async exchangeOidcCode(params: OidcCallbackParams): Promise<OAuthTokenResponse> {
    try {
      const searchParams = new URLSearchParams({
        code: params.code,
        state: params.state,
      });

      const response = await this.axiosInstance.get<OAuthTokenResponse>(
        `${this.OIDC_CALLBACK_PATH}?${searchParams.toString()}`,
        {
          headers: {
            Accept: 'application/json',
          },
        },
      );
      return response.data;
    } catch (error) {
      if (isAxiosError(error)) {
        throw new AgentiumApiError(error.message, error.response?.status);
      }
      throw error;
    }
  }

  /**
   * Parses the OAuth scope string to extract permissions.
   *
   * @param scope - The scope string from the token response
   * @returns Parsed permissions object
   *
   * @example
   * ```typescript
   * const tokens = await client.exchangeOidcCode({ code, state });
   * const permissions = client.parseScope(tokens.scope);
   * if (permissions.isNewUser) {
   *   // Show onboarding
   * }
   * ```
   */
  parseScope(scope: string): ParsedPermissions {
    const parts = scope.split(/\s+/);
    return {
      isUser: parts.includes('user'),
      isNewUser: parts.includes('new_user'),
      did: parts.find((p) => p.startsWith('did:pkh:')) ?? null,
      profileId: parts.find((p) => p.startsWith('profile:'))?.replace('profile:', '') ?? null,
    };
  }

  /**
   * Helper to extract OIDC callback parameters from a URL.
   * Useful for parsing the current URL after redirect.
   *
   * @param url - The URL to parse (defaults to current window.location.href in browser)
   * @returns The callback parameters, or null if code/state are missing
   *
   * @example
   * ```typescript
   * const params = client.parseOidcCallbackUrl();
   * if (params) {
   *   const tokens = await client.exchangeOidcCode(params);
   * }
   * ```
   */
  parseOidcCallbackUrl(url?: string): OidcCallbackParams | null {
    const targetUrl = url ?? (typeof window !== 'undefined' ? window.location.href : '');
    if (!targetUrl) {
      return null;
    }

    const parsedUrl = new URL(targetUrl);
    const code = parsedUrl.searchParams.get('code');
    const state = parsedUrl.searchParams.get('state');

    if (!code || !state) {
      return null;
    }

    return { code, state };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Wallet Authentication Methods
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Request a SIWE challenge message for wallet sign-in.
   *
   * @param address - Wallet address (0x-prefixed for EVM)
   * @param caip2 - CAIP-2 chain identifier (default: Base Mainnet)
   * @returns Challenge message and nonce
   * @throws {Caip2Error} If chain is not supported (only Base Mainnet and Base Sepolia allowed)
   * @throws {AgentiumApiError} If the API request fails
   *
   * @example
   * ```typescript
   * const challenge = await client.requestWalletChallenge(
   *   '0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7',
   *   Caip2.BASE_MAINNET
   * );
   * ```
   */
  async requestWalletChallenge(
    address: string,
    caip2: Caip2 = Caip2.BASE_MAINNET,
  ): Promise<WalletChallengeResponse> {
    assertSupportedChain(caip2);

    try {
      const params = new URLSearchParams({
        address,
        chain_id: caip2.toString(),
      });

      const response = await this.axiosInstance.get<WalletChallengeResponse>(
        `${this.WALLET_CHALLENGE_PATH}?${params.toString()}`,
      );
      return response.data;
    } catch (error) {
      if (isAxiosError(error)) {
        throw new AgentiumApiError(error.message, error.response?.status);
      }
      throw error;
    }
  }

  /**
   * Verify a signed SIWE message and obtain JWT tokens.
   *
   * @param message - The challenge message that was signed
   * @param signature - Hex-encoded signature from wallet (0x-prefixed)
   * @returns OAuth tokens (access_token, refresh_token, etc.)
   * @throws {AgentiumApiError} If signature is invalid or verification fails
   */
  async verifyWalletSignature(message: string, signature: string): Promise<OAuthTokenResponse> {
    try {
      const response = await this.axiosInstance.post<OAuthTokenResponse>(this.WALLET_VERIFY_PATH, {
        message,
        signature,
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
   * Full wallet sign-in flow with user-provided signer.
   *
   * This is the recommended method for browser wallet authentication.
   * The SDK handles the challenge/verify flow; you provide the signing function.
   *
   * @param address - Wallet address (0x-prefixed for EVM)
   * @param caip2 - CAIP-2 chain identifier (only Base Mainnet and Base Sepolia supported)
   * @param signMessage - Function that signs via user's wallet (triggers wallet popup)
   * @returns Identity response with DID and tokens
   * @throws {Caip2Error} If chain is not supported
   * @throws {AgentiumApiError} If any API step fails
   *
   * @example
   * ```typescript
   * // With raw window.ethereum (MetaMask)
   * const response = await client.connectWallet(
   *   address,
   *   Caip2.BASE_MAINNET,
   *   async (msg) => window.ethereum.request({
   *     method: 'personal_sign',
   *     params: [msg, address]
   *   })
   * );
   * ```
   *
   * @example
   * ```typescript
   * // With wagmi
   * const { signMessageAsync } = useSignMessage();
   * const response = await client.connectWallet(
   *   address,
   *   Caip2.BASE_MAINNET,
   *   (msg) => signMessageAsync({ message: msg })
   * );
   * ```
   */
  async connectWallet(
    address: string,
    caip2: Caip2,
    signMessage: MessageSigner,
  ): Promise<ConnectIdentityResponse> {
    assertSupportedChain(caip2);

    // 1. Get challenge from backend
    const challenge = await this.requestWalletChallenge(address, caip2);

    // 2. Request signature from user's wallet (triggers popup)
    const signature = await signMessage(challenge.message);

    // 3. Verify signature and get tokens
    const tokenResponse = await this.verifyWalletSignature(challenge.message, signature);

    // 4. Parse identity from scope
    const { did, isNew } = parseScopeForIdentity(tokenResponse.scope);

    return {
      did,
      badge: { status: isNew ? 'Active' : 'Existing' },
      isNew,
      accessToken: tokenResponse.access_token,
      refreshToken: tokenResponse.refresh_token,
      expiresIn: tokenResponse.expires_in,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Verifiable Credentials Methods
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Configures VC storage for persisting membership credentials.
   * Call this with `createBrowserStorage()` in browser environments.
   *
   * @param storage - Storage implementation to use
   */
  setVcStorage(storage: VcStorage): void {
    this.vcStorage = storage;
  }

  /**
   * Retrieves the stored VC from storage (if any).
   *
   * @returns The stored JWT string, or null if none exists
   */
  getStoredCredential(): string | null {
    return this.vcStorage?.get() ?? null;
  }

  /**
   * Fetches the issuer's DID document from /.well-known/did.json.
   * The DID document contains the public key used to verify VCs.
   *
   * @returns The issuer's DID document
   * @throws {AgentiumApiError} If the request fails
   */
  async fetchIssuerDidDocument(): Promise<DidDocument> {
    try {
      const response = await this.axiosInstance.get<DidDocument>('/.well-known/did.json');
      return response.data;
    } catch (error) {
      if (isAxiosError(error)) {
        throw new AgentiumApiError(error.message, error.response?.status);
      }
      throw error;
    }
  }

  /**
   * Parses a JWT to extract the header (without verification).
   * Delegates to WASM module for parsing.
   *
   * @param jwt - The JWT string
   * @returns Parsed JWT header
   * @throws {WasmVcError} If JWT format is invalid
   */
  parseJwtHeader(jwt: string): JwtHeader {
    return wasmParseJwtHeader(jwt) as JwtHeader;
  }

  /**
   * Extracts the public key JWK from a DID document.
   * If a key ID (kid) is provided, finds the matching verification method.
   * Otherwise, uses the first verification method.
   * Delegates to WASM module for extraction.
   *
   * @param didDocument - The DID document to extract from
   * @param kid - Optional key ID to match (from JWT header)
   * @returns The public key as a JSON string
   * @throws {WasmVcError} If no matching public key is found
   */
  extractPublicKeyJwk(didDocument: DidDocument, kid?: string): string {
    return wasmExtractPublicKeyJwk(JSON.stringify(didDocument), kid);
  }

  /**
   * Fetches a membership credential from the backend.
   * Uses token for authentication.
   *
   * @param token - An auth token
   * @returns Raw JWT string
   * @throws {AgentiumApiError} 401 if token invalid/expired, 403 if user banned
   */
  async fetchMembershipCredential(token: string): Promise<string> {
    try {
      const response = await this.axiosInstance.post<{ credential: string }>(
        '/v1/credentials/membership',
        {},
        { headers: { Authorization: `Bearer ${token}` } },
      );
      const credential = response.data.credential;
      if (!credential) {
        throw new AgentiumApiError('No credential in response from server');
      }
      return credential;
    } catch (error) {
      if (isAxiosError(error)) {
        throw new AgentiumApiError(error.message, error.response?.status);
      }
      throw error;
    }
  }

  /**
   * Verifies a JWT-VC against the issuer's public key.
   * Extracts the key ID from the JWT header, fetches the DID document,
   * finds the matching public key, and uses WASM for Ed25519 verification.
   *
   * @param jwt - The JWT-VC to verify
   * @returns Verification result with validity status, decoded claims, and structured error if invalid
   */
  async verifyCredential(jwt: string): Promise<VerificationResult> {
    await this.wasmReady;
    // Extract kid from JWT header to find the correct key
    const header = this.parseJwtHeader(jwt);
    const didDocument = await this.fetchIssuerDidDocument();
    const publicKeyJwk = this.extractPublicKeyJwk(didDocument, header.kid);
    return verifyJwt(jwt, publicKeyJwk);
  }

  /**
   * Full flow: fetch, verify, and store membership credential.
   * Called immediately after identity connection ("Shadow Launch" mode).
   *
   * Per spec: errors are logged but user sees no change (silent failure).
   *
   * @param token - Server auth token for authorization
   * @returns Verification result (always returns, never throws)
   */
  async connectAndStoreMembership(token: string): Promise<VerificationResult> {
    try {
      const jwt = await this.fetchMembershipCredential(token);
      const result = await this.verifyCredential(jwt);

      if (result.valid && this.vcStorage) {
        this.vcStorage.set(jwt);
        // TODO: Log analytics: "VC Success"
      } else if (!result.valid) {
        // TODO: Log analytics: "VC Verification Failed"
        console.warn('[Agentium] VC verification failed:', result.error);
      }

      return result;
    } catch (error) {
      // Silent failure per spec - log but don't throw
      // Note: verifyJwt no longer throws; this only catches fetch/DID errors
      console.warn('[Agentium] VC fetch/verify error:', error);
      return {
        valid: false,
        error: {
          code: 'VERIFICATION_FAILED',
          message: error instanceof Error ? error.message : String(error),
        },
      };
    }
  }
}
