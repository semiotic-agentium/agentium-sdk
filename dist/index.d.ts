import type { VcStorage, VerificationResult, DidDocument, JwtHeader } from './vc/index.js';
export * from './vc/index.js';
export { ensureWasmReady, initLogging, verifyJwt, generateKeypair, getPublicKey } from './wasm.js';
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
export type GrantType = 'api_key' | 'refresh_token' | 'privy_id_token' | 'google_id_token' | 'external_google';
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
export declare class AgentiumApiError extends Error {
    readonly statusCode: number | undefined;
    constructor(message: string, statusCode?: number);
}
/**
 * A client for interacting with the Agentium API.
 */
export declare class AgentiumClient {
    private readonly axiosInstance;
    private readonly DEFAULT_BASE_URL;
    private readonly OAUTH_TOKEN_PATH;
    private vcStorage;
    /**
     * Creates an instance of the AgentiumClient.
     * @param options - Configuration options for the client.
     */
    constructor(options?: AgentiumClientOptions);
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
    connectGoogleIdentity(googleToken: string, options?: ConnectGoogleIdentityOptions): Promise<ConnectIdentityResponse>;
    /**
     * Exchanges an API key for JWT tokens (M2M authentication).
     * @param apiKey - The API key to exchange.
     * @returns A promise that resolves with the OAuth token response.
     * @throws {AgentiumApiError} Will throw a custom API error if the call fails.
     */
    exchangeApiKey(apiKey: string): Promise<OAuthTokenResponse>;
    /**
     * Refreshes an access token using a refresh token.
     * @param refreshTokenValue - The refresh token to use.
     * @returns A promise that resolves with the new OAuth token response.
     * @throws {AgentiumApiError} Will throw a custom API error if the call fails.
     */
    refreshToken(refreshTokenValue: string): Promise<OAuthTokenResponse>;
    /**
     * Exchanges a Privy ID token for JWT tokens.
     * @param idToken - The Privy ID token to exchange.
     * @returns A promise that resolves with the OAuth token response.
     * @throws {AgentiumApiError} Will throw a custom API error if the call fails.
     */
    exchangePrivyToken(idToken: string): Promise<OAuthTokenResponse>;
    /**
     * Configures VC storage for persisting membership credentials.
     * Call this with `createBrowserStorage()` in browser environments.
     *
     * @param storage - Storage implementation to use
     */
    setVcStorage(storage: VcStorage): void;
    /**
     * Retrieves the stored VC from storage (if any).
     *
     * @returns The stored JWT string, or null if none exists
     */
    getStoredCredential(): string | null;
    /**
     * Fetches the issuer's DID document from /.well-known/did.json.
     * The DID document contains the public key used to verify VCs.
     *
     * @returns The issuer's DID document
     * @throws {AgentiumApiError} If the request fails
     */
    fetchIssuerDidDocument(): Promise<DidDocument>;
    /**
     * Parses a JWT to extract the header (without verification).
     *
     * @param jwt - The JWT string
     * @returns Parsed JWT header
     * @throws {AgentiumApiError} If JWT format is invalid
     */
    parseJwtHeader(jwt: string): JwtHeader;
    /**
     * Extracts the public key JWK from a DID document.
     * If a key ID (kid) is provided, finds the matching verification method.
     * Otherwise, uses the first verification method.
     *
     * @param didDocument - The DID document to extract from
     * @param kid - Optional key ID to match (from JWT header)
     * @returns The public key as a JSON string
     * @throws {AgentiumApiError} If no matching public key is found
     */
    extractPublicKeyJwk(didDocument: DidDocument, kid?: string): string;
    /**
     * Fetches a membership credential from the backend.
     * Uses Privy auth token for authentication.
     *
     * @param privyToken - Privy auth token (NOT the accessToken from OAuth)
     * @returns Raw JWT string
     * @throws {AgentiumApiError} 401 if token invalid/expired, 403 if user banned
     */
    fetchMembershipCredential(privyToken: string): Promise<string>;
    /**
     * Verifies a JWT-VC against the issuer's public key.
     * Extracts the key ID from the JWT header, fetches the DID document,
     * finds the matching public key, and uses WASM for Ed25519 verification.
     *
     * @param jwt - The JWT-VC to verify
     * @returns Verification result with validity status, decoded claims, and structured error if invalid
     */
    verifyCredential(jwt: string): Promise<VerificationResult>;
    /**
     * Full flow: fetch, verify, and store membership credential.
     * Called immediately after identity connection ("Shadow Launch" mode).
     *
     * Per spec: errors are logged but user sees no change (silent failure).
     *
     * @param privyToken - Privy auth token
     * @returns Verification result (always returns, never throws)
     */
    connectAndStoreMembership(privyToken: string): Promise<VerificationResult>;
}
//# sourceMappingURL=index.d.ts.map