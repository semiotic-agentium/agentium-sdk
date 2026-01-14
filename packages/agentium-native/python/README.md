<!-- SPDX-FileCopyrightText: 2025 Semiotic AI, Inc. -->
<!-- SPDX-License-Identifier: MIT -->

# Agentium SDK for Python

Python SDK for Agentium Network - DID and Verifiable Credentials.

## Installation

```bash
pip install agentium-sdk
```

## Quick Start

### Google Sign-In

```python
import agentium_sdk

# Connect with Google Sign-In (async)
wallet_address, did = await agentium_sdk.connect_google(google_id_token)

# Or use the sync version
wallet_address, did = agentium_sdk.connect_google_sync(google_id_token)
```

### Wallet Sign-In (SIWE/EIP-4361)

```python
import agentium_sdk

# Connect with wallet using local signing (async)
wallet_address, did = await agentium_sdk.connect_wallet(
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
    chain_id="eip155:84532",  # CAIP-2 format (Base Sepolia)
    private_key="ac0974bfc...",  # hex string or bytes
)

# Or use the sync version
wallet_address, did = agentium_sdk.connect_wallet_sync(
    address, chain_id, private_key
)
```

## AgentiumClient

The `AgentiumClient` is the main interface for API interactions.

### Configuration

```python
from agentium_sdk import AgentiumClient

# Default: connects to https://api.agentium.network
async with AgentiumClient() as client:
    pass

# Custom endpoint
async with AgentiumClient(base_url="https://custom.endpoint") as client:
    pass
```

### Methods

#### `connect_google_identity(google_token: str) -> ConnectIdentityResponse`

Connect a Google identity to create/retrieve a DID.

```python
response = await client.connect_google_identity(google_id_token)
print(response.did)           # did:pkh:eip155:1:0x...
print(response.access_token)  # JWT for authenticated calls
print(response.is_new)        # True if newly created
```

#### `exchange_api_key(api_key: str) -> OAuthTokenResponse`

Exchange an API key for JWT tokens (M2M authentication).

```python
response = await client.exchange_api_key(api_key)
print(response.access_token)
print(response.refresh_token)
```

#### `refresh_token(refresh_token: str) -> OAuthTokenResponse`

Refresh an expired access token.

```python
response = await client.refresh_token(old_refresh_token)
```

#### `fetch_membership_credential(token: str) -> str`

Fetch a membership credential JWT.

```python
credential_jwt = await client.fetch_membership_credential(access_token)
```

#### `fetch_issuer_did_document() -> dict[str, Any]`

Fetch the issuer's DID document from `/.well-known/did.json`.

```python
did_document = await client.fetch_issuer_did_document()
print(did_document["id"])  # did:web:api.agentium.network
```

#### `verify_credential(jwt: str) -> VerificationResult`

Verify a credential against the issuer's public key (fetches DID document automatically).

```python
result = await client.verify_credential(credential_jwt)
if result.valid:
    print(result.claims)  # dict with JWT claims
```

#### `request_wallet_challenge(address: str, chain_id: str) -> WalletChallengeResponse`

Request a SIWE challenge message for wallet sign-in.

```python
challenge = await client.request_wallet_challenge(
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
    chain_id="eip155:84532",  # CAIP-2 format
)
print(challenge.message)  # SIWE message to sign
print(challenge.nonce)    # Unique nonce for replay protection
```

#### `verify_wallet_signature(message: str, signature: str) -> OAuthTokenResponse`

Verify a signed challenge and obtain JWT tokens.

```python
response = await client.verify_wallet_signature(challenge.message, signature)
print(response.access_token)
print(response.refresh_token)
```

#### `connect_wallet(address: str, chain_id: str, private_key: bytes | str) -> ConnectIdentityResponse`

Full wallet sign-in flow with local signing (challenge → sign → verify).

```python
response = await client.connect_wallet(
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
    chain_id="eip155:84532",
    private_key="ac0974bfc...",  # hex string or bytes
)
print(response.did)           # did:pkh:eip155:84532:0x...
print(response.access_token)  # JWT for authenticated calls
print(response.is_new)        # True if newly created
```

## Native Functions

Low-level cryptographic operations powered by Rust.

### `verify_jwt(jwt: str, public_key_jwk: str) -> VerificationResult`

Verify a JWT signature against a public key.

```python
from agentium_sdk import verify_jwt

result = verify_jwt(jwt_string, public_key_jwk_json)
if result.valid:
    print(result.claims)           # dict[str, Any]
else:
    print(result.error.code)       # e.g., "JWT_EXPIRED"
    print(result.error.message)
```

### `parse_jwt_header(jwt: str) -> JwtHeader`

Parse JWT header without verification.

```python
from agentium_sdk import parse_jwt_header

header = parse_jwt_header(jwt_string)
print(header.alg)  # "EdDSA"
print(header.kid)  # Key ID for DID document lookup
```

### `extract_public_key_jwk(did_document_json: str, kid: str | None) -> str`

Extract a public key from a DID document.

```python
from agentium_sdk import extract_public_key_jwk

public_key_jwk = extract_public_key_jwk(did_doc_json, kid="#key-1")
```

### `generate_keypair() -> GeneratedKeyPair`

Generate a new Ed25519 key pair.

```python
from agentium_sdk import generate_keypair

keypair = generate_keypair()
print(keypair.public_key_jwk)   # Safe to share
print(keypair.private_key_jwk)  # Keep secret!
```

### `get_public_key(private_key_jwk: str) -> str`

Derive public key from a private key.

```python
from agentium_sdk import get_public_key

public_jwk = get_public_key(private_key_jwk_json)
```

### `sign_challenge(message: bytes, chain_id: str, private_key: bytes) -> str`

Sign a wallet authentication challenge message.

```python
from agentium_sdk import sign_challenge

signature = sign_challenge(
    message=challenge_message.encode("utf-8"),
    chain_id="eip155:84532",
    private_key=private_key_bytes,
)
print(signature)  # 0x-prefixed hex signature
```

### `validate_caip2(chain_id: str) -> bool`

Validate a CAIP-2 chain identifier format.

```python
from agentium_sdk import validate_caip2

if validate_caip2("eip155:84532"):
    print("Valid chain ID")
```

## Telemetry

Enable structured tracing with a custom callback.

```python
from agentium_sdk import init_tracing

def telemetry_handler(event: dict):
    """Receives events with: kind, level, target, name, fields, ts_ms"""
    print(f"[{event['level']}] {event['target']}: {event['fields']}")

# Initialize once per process
init_tracing(telemetry_handler, "debug")  # filter: "info", "debug", "agentium=trace"
```

**Note:** `init_tracing` can only be called once. Subsequent calls are ignored.

## Types

| Type | Description |
|------|-------------|
| `ConnectIdentityResponse` | DID, tokens, badge status, `is_new` flag |
| `OAuthTokenResponse` | `access_token`, `refresh_token`, `expires_in`, `scope` |
| `WalletChallengeResponse` | `message`, `nonce` for wallet sign-in challenge |
| `Caip2` | Parsed CAIP-2 chain identifier with `namespace` and `reference` |
| `VerificationResult` | `valid`, `claims` (dict), `error` |
| `VerificationError` | `code`, `message` |
| `JwtHeader` | `alg`, `typ`, `kid` |
| `GeneratedKeyPair` | `private_key_jwk`, `public_key_jwk` |
| `Badge` | `status` |

## Exceptions

### `AgentiumApiError`

Raised on API failures.

```python
from agentium_sdk import AgentiumApiError

try:
    await client.connect_google_identity(invalid_token)
except AgentiumApiError as e:
    print(e.message)
    print(e.status_code)  # 401, 403, etc.
```

## Python SDK Documentation

To build and serve docs locally:

```bash
# From the repository root, navigate to the Python SDK directory
cd packages/agentium-native/python

# Install docs dependencies
pip install -e ".[docs]"

# Build the SDK (required for mkdocstrings to inspect types)
maturin develop

# Serve docs locally with hot-reload
mkdocs serve

# Or build static site
mkdocs build
```

## Development

```bash
# Install build tool
pip install maturin

# Build and install in development mode
maturin develop

# Run tests
pip install -e ".[dev]"
pytest
```

## License

MIT License - see LICENSE file for details.
