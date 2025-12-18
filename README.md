<!--
SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.

SPDX-License-Identifier: MIT
-->

# @semiotic-labs/agentium-sdk

TypeScript SDK for interacting with the Agentium Network API. Supports identity connection, OAuth token management, and W3C Verifiable Credentials (VCs) with Ed25519 signatures.

## Installation

```bash
npm install @semiotic-labs/agentium-sdk
```

## Quick Start

```typescript
import { AgentiumClient } from '@semiotic-labs/agentium-sdk';

const client = new AgentiumClient();

// Connect with Google identity
const response = await client.connectGoogleIdentity(googleJwtToken);
console.log('User DID:', response.did);
console.log('Access Token:', response.accessToken);
```

## API Reference

### Client Setup

```typescript
import { AgentiumClient } from '@semiotic-labs/agentium-sdk';

// Default: https://api.agentium.network
const client = new AgentiumClient();

// Custom endpoint (for local/staging)
const client = new AgentiumClient({ baseURL: 'http://localhost:8080' });
```

### Identity Connection

#### `connectGoogleIdentity(googleToken, options?)`

Connects a Google identity to an Agentium identity.

```typescript
// Standard Google Sign-In
const response = await client.connectGoogleIdentity(googleJwtToken);

// External OAuth (e.g., zkLogin) - skip audience validation
const response = await client.connectGoogleIdentity(googleJwtToken, {
  skipAudienceValidation: true,
});
```

**Returns:** `ConnectIdentityResponse` with `did`, `accessToken`, `refreshToken`, `expiresIn`, `isNew`, `badge`

### Token Management

#### `exchangeApiKey(apiKey)`

Exchanges an API key for JWT tokens (M2M authentication).

```typescript
const tokens = await client.exchangeApiKey('ak_your_api_key');
```

#### `refreshToken(refreshTokenValue)`

Refreshes an access token using a refresh token.

```typescript
const newTokens = await client.refreshToken(currentRefreshToken);
```

#### `exchangePrivyToken(idToken)`

Exchanges a Privy ID token for JWT tokens.

```typescript
const tokens = await client.exchangePrivyToken(privyIdToken);
```

### Verifiable Credentials

The SDK supports W3C Verifiable Credentials issued as JWTs with Ed25519 signatures.

#### Storage Setup

```typescript
import { createBrowserStorage, createMemoryStorage } from '@semiotic-labs/agentium-sdk';

// Browser environment (uses localStorage)
client.setVcStorage(createBrowserStorage());

// Node.js or testing (in-memory)
client.setVcStorage(createMemoryStorage());
```

#### `fetchMembershipCredential(token)`

Fetches a membership credential from the backend.

```typescript
const vcJwt = await client.fetchMembershipCredential(authToken);
```

#### `verifyCredential(jwt)`

Verifies a JWT-VC against the issuer's public key.

```typescript
const result = await client.verifyCredential(vcJwt);

if (result.valid) {
  console.log('Subject DID:', result.claims?.sub);
} else {
  console.error('Error:', result.error?.code, result.error?.message);
}
```

#### `connectAndStoreMembership(token)`

Full flow: fetch, verify, and store a membership credential.

```typescript
const result = await client.connectAndStoreMembership(authToken);
```

#### `getStoredCredential()`

Retrieves the stored VC JWT from storage.

```typescript
const storedVc = client.getStoredCredential();
```

### WASM Utilities

Low-level cryptographic operations for Ed25519.

```typescript
import {
  ensureWasmReady,
  verifyJwt,
  generateKeypair,
  getPublicKey,
} from '@semiotic-labs/agentium-sdk';

// For bundlers like Vite, provide WASM URL explicitly
import wasmUrl from '@semiotic-labs/agentium-sdk/wasm?url';
await ensureWasmReady(wasmUrl);

// Generate key pair
const { privateKey, publicKey } = await generateKeypair();

// Verify JWT directly
const result = await verifyJwt(jwtString, publicKeyJwk);
```

### Error Handling

All API methods throw `AgentiumApiError` on failure:

```typescript
import { AgentiumApiError } from '@semiotic-labs/agentium-sdk';

try {
  await client.connectGoogleIdentity(token);
} catch (error) {
  if (error instanceof AgentiumApiError) {
    console.error(`API Error (${error.statusCode}): ${error.message}`);
  }
}
```

## API Documentation

Generate full API documentation from source:

```bash
npm run docs
```

Documentation is output to the `docs/` folder.

## Development

### Setup

```bash
git clone https://github.com/semiotic-agentium/agentium-sdk.git
cd agentium-sdk
npm install
```

### Scripts

```bash
npm test          # Run tests
npm run build     # Build (WASM + TypeScript)
npm run docs      # Generate API docs
npm run lint      # Lint code
npm run check     # Lint + format check
```

### REUSE Compliance

This project follows the [REUSE Specification](https://reuse.software/spec/).

```bash
pip install reuse          # Install REUSE tool
npm run reuse:check        # Verify compliance
npm run reuse:write        # Apply SPDX headers
```

## License

MIT
