# Agentium SDK for Python

Python SDK for Agentium Network - DID and Verifiable Credentials.

## Installation

Once we have our sdk published, you can:

```bash
pip install agentium-sdk
```

## Quick Start

```python
import agentium-sdk

# Connect with Google Sign-In (async)
wallet_address, did = await agentium.connect_google(google_id_token)

# Or use the sync version
wallet_address, did = agentium.connect_google_sync(google_id_token)
```

## AgentiumClient

The `AgentiumClient` is the main interface for API interactions.

### Configuration

```python
from agentium import AgentiumClient

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
    claims = result.claims_dict()
```

## Native Functions

Low-level cryptographic operations powered by Rust.

### `verify_jwt(jwt: str, public_key_jwk: str) -> VerificationResult`

Verify a JWT signature against a public key.

```python
from agentium import verify_jwt

result = verify_jwt(jwt_string, public_key_jwk_json)
if result.valid:
    claims = result.claims_dict()  # dict[str, Any]
else:
    print(result.error.code)       # e.g., "JWT_EXPIRED"
    print(result.error.message)
```

### `parse_jwt_header(jwt: str) -> JwtHeader`

Parse JWT header without verification.

```python
from agentium import parse_jwt_header

header = parse_jwt_header(jwt_string)
print(header.alg)  # "EdDSA"
print(header.kid)  # Key ID for DID document lookup
```

### `extract_public_key_jwk(did_document_json: str, kid: str | None) -> str`

Extract a public key from a DID document.

```python
from agentium import extract_public_key_jwk

public_key_jwk = extract_public_key_jwk(did_doc_json, kid="#key-1")
```

### `generate_keypair() -> GeneratedKeyPair`

Generate a new Ed25519 key pair.

```python
from agentium import generate_keypair

keypair = generate_keypair()
print(keypair.public_key_jwk)   # Safe to share
print(keypair.private_key_jwk)  # Keep secret!
```

### `get_public_key(private_key_jwk: str) -> str`

Derive public key from a private key.

```python
from agentium import get_public_key

public_jwk = get_public_key(private_key_jwk_json)
```

## Telemetry

Enable structured tracing with a custom callback.

```python
from agentium import init_tracing

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
| `VerificationResult` | `valid`, `claims`, `error`, `claims_dict()` |
| `VerificationError` | `code`, `message` |
| `JwtHeader` | `alg`, `typ`, `kid` |
| `GeneratedKeyPair` | `private_key_jwk`, `public_key_jwk` |
| `Badge` | `status` |

## Exceptions

### `AgentiumApiError`

Raised on API failures.

```python
from agentium import AgentiumApiError

try:
    await client.connect_google_identity(invalid_token)
except AgentiumApiError as e:
    print(e.message)
    print(e.status_code)  # 401, 403, etc.
```

## Documentation

Full API documentation is available at:

- **Online**: [semiotic-ai.github.io/agentium-sdk/python/](https://semiotic-ai.github.io/agentium-sdk/python/)

To build and serve docs locally:

```bash
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
