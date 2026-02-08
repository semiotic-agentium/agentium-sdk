<!--
SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.

SPDX-License-Identifier: BUSL-1.1
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

// For bundlers like Vite that require explicit WASM URL
import wasmUrl from '@semiotic-labs/agentium-sdk/wasm?url';
const client = new AgentiumClient({ wasmUrl });
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

Low-level cryptographic operations for Ed25519. WASM is automatically initialized on first use — no manual setup required.

```typescript
import { verifyJwt, generateKeypair, getPublicKey } from '@semiotic-labs/agentium-sdk';

// Generate key pair
const { privateKey, publicKey } = await generateKeypair();

// Verify JWT directly
const result = await verifyJwt(jwtString, publicKeyJwk);
```

#### Bundler Configuration (Vite, etc.)

For bundlers like Vite that require explicit WASM URL resolution, pass `wasmUrl` to the client constructor (see [Client Setup](#client-setup)).

If using low-level WASM utilities directly (without `AgentiumClient`), initialize manually:

```typescript
import { ensureWasmReady } from '@semiotic-labs/agentium-sdk';
import wasmUrl from '@semiotic-labs/agentium-sdk/wasm?url';

await ensureWasmReady(wasmUrl);
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

### Telemetry

The SDK provides a flexible telemetry system that forwards tracing events from the WASM layer to JavaScript. Consumers can define custom sinks to handle events (logging, analytics, monitoring services, etc.).

> **Note:** The WASM layer currently emits events only — spans are not yet supported.

#### Initialization

Telemetry must be initialized after WASM is ready and can only be called once. If not initialized, no telemetry is emitted (silent by default).

```typescript
import { ensureWasmReady, initTelemetry, consoleSink } from '@semiotic-labs/agentium-sdk';

await ensureWasmReady();
initTelemetry({ sink: consoleSink });
```

#### Built-in Sinks

- **`consoleSink`** — Logs events to the browser/Node console using the appropriate method (`console.error`, `console.warn`, etc.)
- **`nullSink`** — Discards all events (useful for explicitly disabling telemetry)

#### Filtering Events

Filter events by level or target module:

```typescript
import { withLevelFilter, withTargetFilter, consoleSink } from '@semiotic-labs/agentium-sdk';

// Only log errors and warnings
const errorSink = withLevelFilter(['error', 'warn'], consoleSink);

// Only log events from agentium modules
const agentiumSink = withTargetFilter(['agentium_sdk'], consoleSink);
```

#### Composing Sinks

Combine multiple sinks to forward events to different destinations:

```typescript
import { composeSinks, withLevelFilter, consoleSink, initTelemetry } from '@semiotic-labs/agentium-sdk';

const myAnalyticsSink = (event) => {
  // Send to your analytics service
  analytics.track('sdk_event', event);
};

initTelemetry({
  sink: composeSinks(
    withLevelFilter(['error', 'warn', 'info'], consoleSink),
    myAnalyticsSink
  ),
  filter: 'agentium_sdk=debug' // tracing-subscriber EnvFilter syntax
});
```

#### Event Structure

Events passed to sinks have the following shape:

```typescript
interface TelemetryEvent {
  kind: 'event';                    // Event type (currently always "event")
  level: 'error' | 'warn' | 'info' | 'debug' | 'trace';
  target: string;                   // Module path (e.g., "agentium_sdk_wasm::vc")
  name?: string;                    // Event name
  fields: Record<string, unknown>;  // Structured fields from the event
  ts_ms: number;                    // Timestamp in milliseconds
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
npm test              # Run tests
npm run build         # Build (WASM + TypeScript)
npm run docs          # Generate API docs
npm run lint          # Lint code
npm run check         # Lint + format check
npm run check:python  # Type-check Python code (mypy)
npm run format:all    # Format all code (TS, Python, Rust)
npm run format:rust   # Format Rust code
```

### REUSE Compliance

This project follows the [REUSE Specification](https://reuse.software/spec/).

```bash
pip install reuse          # Install REUSE tool
npm run reuse:check        # Verify compliance
npm run reuse:write        # Apply SPDX headers
```

## Python SDK

A Python SDK is also available with equivalent functionality. See the [Python SDK documentation](packages/agentium-native/python/README.md) for installation and usage.

```bash
pip install agentium
```

## License

This project is licensed under the Business Source License 1.1. See the [LICENSE](./LICENSE) file for details.
