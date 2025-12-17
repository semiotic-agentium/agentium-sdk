// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT
import axios, { isAxiosError } from 'axios';
import { verifyJwt } from './wasm.js';
// Re-export VC module types and utilities
export * from './vc/index.js';
export { ensureWasmReady, initLogging, verifyJwt, generateKeypair, getPublicKey } from './wasm.js';
/**
 * Custom error class for API-related errors from the AgentiumClient.
 */
export class AgentiumApiError extends Error {
    statusCode;
    constructor(message, statusCode) {
        super(message);
        this.name = 'AgentiumApiError';
        this.statusCode = statusCode;
    }
}
/**
 * Parses the OAuth scope string to extract the DID and new_user flag.
 * Scope format: "user did:pkh:eip155:1:0x... [new_user]"
 */
function parseScopeForIdentity(scope) {
    const parts = scope.split(/\s+/);
    const did = parts.find((part) => part.startsWith('did:pkh:')) || '';
    const isNew = parts.includes('new_user');
    return { did, isNew };
}
/**
 * A client for interacting with the Agentium API.
 */
export class AgentiumClient {
    axiosInstance;
    DEFAULT_BASE_URL = 'https://api.agentium.network';
    OAUTH_TOKEN_PATH = '/oauth/token';
    vcStorage = null;
    /**
     * Creates an instance of the AgentiumClient.
     * @param options - Configuration options for the client.
     */
    constructor(options = {}) {
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
    async connectGoogleIdentity(googleToken, options = {}) {
        const grantType = options.skipAudienceValidation
            ? 'external_google'
            : 'google_id_token';
        try {
            const response = await this.axiosInstance.post(this.OAUTH_TOKEN_PATH, {
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
        }
        catch (error) {
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
    async exchangeApiKey(apiKey) {
        try {
            const response = await this.axiosInstance.post(this.OAUTH_TOKEN_PATH, {
                grant_type: 'api_key',
                api_key: apiKey,
            });
            return response.data;
        }
        catch (error) {
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
    async refreshToken(refreshTokenValue) {
        try {
            const response = await this.axiosInstance.post(this.OAUTH_TOKEN_PATH, {
                grant_type: 'refresh_token',
                refresh_token: refreshTokenValue,
            });
            return response.data;
        }
        catch (error) {
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
    async exchangePrivyToken(idToken) {
        try {
            const response = await this.axiosInstance.post(this.OAUTH_TOKEN_PATH, {
                grant_type: 'privy_id_token',
                id_token: idToken,
            });
            return response.data;
        }
        catch (error) {
            if (isAxiosError(error)) {
                throw new AgentiumApiError(error.message, error.response?.status);
            }
            throw error;
        }
    }
    // ─────────────────────────────────────────────────────────────────────────────
    // Verifiable Credentials (VC) Methods
    // ─────────────────────────────────────────────────────────────────────────────
    /**
     * Configures VC storage for persisting membership credentials.
     * Call this with `createBrowserStorage()` in browser environments.
     *
     * @param storage - Storage implementation to use
     */
    setVcStorage(storage) {
        this.vcStorage = storage;
    }
    /**
     * Retrieves the stored VC from storage (if any).
     *
     * @returns The stored JWT string, or null if none exists
     */
    getStoredCredential() {
        return this.vcStorage?.get() ?? null;
    }
    /**
     * Fetches the issuer's DID document from /.well-known/did.json.
     * The DID document contains the public key used to verify VCs.
     *
     * @returns The issuer's DID document
     * @throws {AgentiumApiError} If the request fails
     */
    async fetchIssuerDidDocument() {
        try {
            const response = await this.axiosInstance.get('/.well-known/did.json');
            return response.data;
        }
        catch (error) {
            if (isAxiosError(error)) {
                throw new AgentiumApiError(error.message, error.response?.status);
            }
            throw error;
        }
    }
    /**
     * Parses a JWT to extract the header (without verification).
     *
     * @param jwt - The JWT string
     * @returns Parsed JWT header
     * @throws {AgentiumApiError} If JWT format is invalid
     */
    parseJwtHeader(jwt) {
        const parts = jwt.split('.');
        if (parts.length !== 3) {
            throw new AgentiumApiError('Invalid JWT format: expected 3 parts');
        }
        const headerPart = parts[0];
        if (!headerPart) {
            throw new AgentiumApiError('Invalid JWT format: missing header');
        }
        try {
            const headerJson = atob(headerPart.replace(/-/g, '+').replace(/_/g, '/'));
            return JSON.parse(headerJson);
        }
        catch {
            throw new AgentiumApiError('Invalid JWT header encoding');
        }
    }
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
    extractPublicKeyJwk(didDocument, kid) {
        const methods = didDocument.verificationMethod;
        if (!methods || methods.length === 0) {
            throw new AgentiumApiError('No verification methods found in DID document');
        }
        let verificationMethod = methods[0];
        // If kid is provided, find the matching verification method
        if (kid) {
            const matched = methods.find((m) => m.id === kid);
            if (matched) {
                verificationMethod = matched;
            }
            else {
                // kid might be just the fragment (e.g., "key-1"), try matching suffix
                const matchedByFragment = methods.find((m) => m.id.endsWith(`#${kid}`) || m.id === kid);
                if (matchedByFragment) {
                    verificationMethod = matchedByFragment;
                }
            }
        }
        if (!verificationMethod?.publicKeyJwk) {
            throw new AgentiumApiError(kid ? `No public key found for kid: ${kid}` : 'No public key found in DID document');
        }
        return JSON.stringify(verificationMethod.publicKeyJwk);
    }
    /**
     * Fetches a membership credential from the backend.
     * Uses Privy auth token for authentication.
     *
     * @param privyToken - Privy auth token (NOT the accessToken from OAuth)
     * @returns Raw JWT string
     * @throws {AgentiumApiError} 401 if token invalid/expired, 403 if user banned
     */
    async fetchMembershipCredential(privyToken) {
        try {
            const response = await this.axiosInstance.post('/v1/credentials/membership', {}, { headers: { Authorization: `Bearer ${privyToken}` } });
            return response.data.vc;
        }
        catch (error) {
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
    async verifyCredential(jwt) {
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
     * @param privyToken - Privy auth token
     * @returns Verification result (always returns, never throws)
     */
    async connectAndStoreMembership(privyToken) {
        try {
            const jwt = await this.fetchMembershipCredential(privyToken);
            const result = await this.verifyCredential(jwt);
            if (result.valid && this.vcStorage) {
                this.vcStorage.set(jwt);
                // TODO: Log analytics: "VC Success"
            }
            else if (!result.valid) {
                // TODO: Log analytics: "VC Verification Failed"
                console.warn('[Agentium] VC verification failed:', result.error);
            }
            return result;
        }
        catch (error) {
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
//# sourceMappingURL=index.js.map