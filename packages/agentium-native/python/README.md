<!--
SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.

SPDX-License-Identifier: BUSL-1.1
-->


# Agentium SDK for Python

Python SDK for Agentium Network - DID and Verifiable Credentials.

## Installation

```bash
pip install agentium-sdk
```

## Requirements

- **Python**: 3.10 or higher
- **For end users**: No additional dependencies (prebuilt wheels available for supported platforms)
- **For development/building from source**:
  - Rust toolchain (1.70+) - [Install Rust](https://rustup.rs/)
  - Maturin build tool: `pip install maturin`

## Platform Support

Prebuilt wheels are available for the following platforms:

| Platform | Architecture | Wheel Available |
|----------|--------------|------------------|
| Linux | x86_64 | ✅ |
| Linux | aarch64 (ARM64) | ❌ (build from source) |
| macOS | x86_64 (Intel) | ✅ |
| macOS | aarch64 (Apple Silicon) | ✅ |
| Windows | x86_64 | ✅ |

### Installing on Unsupported Platforms

For platforms without prebuilt wheels (e.g., Linux aarch64/ARM64), pip will automatically attempt to build from the source distribution. This requires:

1. **Rust toolchain** (1.70+):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Install the SDK** (pip will compile from source):
   ```bash
   pip install agentium-sdk
   ```

The build process may take a few minutes as it compiles the native Rust code.

## Quick Start

### Google Sign-In

```python
import agentium_sdk

# Connect with Google Sign-In (async)
wallet_address, did = await agentium_sdk.connect_google(google_id_token)

# Or use the sync version
wallet_address, did = agentium_sdk.connect_google_sync(google_id_token)
```

**Note:** The `google_id_token` is obtained from Google's OAuth 2.0 authentication flow. See [Google Identity documentation](https://developers.google.com/identity/gsi/web/guides/overview) for implementation details.

### Wallet Sign-In (SIWE/EIP-4361)

```python
import agentium_sdk
import os

# Connect with wallet using local signing (async)
# Uses Base mainnet (eip155:8453) by default
wallet_address, did = await agentium_sdk.connect_wallet(
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
    private_key=os.getenv("WALLET_PRIVATE_KEY"),  # hex string or bytes
)

# Or specify a different chain (e.g., testnet) using Caip2
from agentium_sdk import Caip2

wallet_address, did = await agentium_sdk.connect_wallet(
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
    private_key=os.getenv("WALLET_PRIVATE_KEY"),
    chain_id=Caip2.BASE_SEPOLIA,  # or "eip155:84532" for testnet
)

# Sync version available
wallet_address, did = agentium_sdk.connect_wallet_sync(address, private_key)
```

**Security Warning:** Never hardcode private keys in your source code. Always use environment variables, secure key management systems, or hardware wallets in production.

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

#### `request_wallet_challenge(address: str, chain_id: Caip2 | str = Caip2.BASE_MAINNET) -> WalletChallengeResponse`

Request a SIWE challenge message for wallet sign-in.

```python
# Uses Base mainnet by default
challenge = await client.request_wallet_challenge(
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
)
print(challenge.message)  # SIWE message to sign
print(challenge.nonce)    # Unique nonce for replay protection

# Or specify testnet explicitly
from agentium_sdk import Caip2

challenge = await client.request_wallet_challenge(
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
    chain_id=Caip2.BASE_SEPOLIA,  # or "eip155:84532" for testnet
)
```

#### `verify_wallet_signature(message: str, signature: str) -> OAuthTokenResponse`

Verify a signed challenge and obtain JWT tokens.

```python
response = await client.verify_wallet_signature(challenge.message, signature)
print(response.access_token)
print(response.refresh_token)
```

#### `connect_wallet(address: str, private_key: bytes | str, chain_id: Caip2 | str = Caip2.BASE_MAINNET) -> ConnectIdentityResponse`

Full wallet sign-in flow with local signing (challenge → sign → verify).

```python
import os

# Uses Base mainnet by default
response = await client.connect_wallet(
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
    private_key=os.getenv("WALLET_PRIVATE_KEY"),  # hex string or bytes
)
print(response.did)           # did:pkh:eip155:8453:0x...
print(response.access_token)  # JWT for authenticated calls
print(response.is_new)        # True if newly created

# Or specify testnet explicitly
from agentium_sdk import Caip2

response = await client.connect_wallet(
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
    private_key=os.getenv("WALLET_PRIVATE_KEY"),
    chain_id=Caip2.BASE_SEPOLIA,  # for testnet
)
```

**Security Note:** Use secure key management practices. Never commit private keys to version control.

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
import os

# Load private key securely from environment
private_key = bytes.fromhex(os.getenv("WALLET_PRIVATE_KEY"))

signature = sign_challenge(
    message=challenge_message.encode("utf-8"),
    chain_id="eip155:84532",
    private_key=private_key,
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
| `Caip2` | Parsed CAIP-2 chain identifier with `namespace` and `reference`. Constants: `Caip2.BASE_SEPOLIA`, `Caip2.BASE_MAINNET` |
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

### `Caip2Error`

Raised when CAIP-2 chain identifier parsing fails.

```python
from agentium_sdk import Caip2, Caip2Error

try:
    caip2 = Caip2.parse("invalid-chain-id")
except Caip2Error as e:
    print(e)  # CAIP-2 identifier must contain a colon separator
```

## Development

This SDK is a Python binding to native Rust code, providing high-performance cryptographic operations. Building from source requires the Rust toolchain.

### Setup

```bash
# Install Rust toolchain (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Maturin (build tool for Rust-based Python packages)
pip install maturin

# Build and install in development mode
# This compiles the Rust code and creates a Python package
maturin develop

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

### About Maturin

[Maturin](https://github.com/PyO3/maturin) is the build tool that bridges Rust and Python, compiling the native Rust extensions and packaging them as a Python wheel. The `maturin develop` command builds the Rust code in debug mode and installs it in your current Python environment.

## Building Documentation

**Note:** This section is for SDK contributors who want to build and preview the documentation locally.

To build and serve docs:

```bash
# From the repository root, navigate to the Python SDK directory
cd packages/agentium-native/python

# Install documentation dependencies
pip install -e ".[docs]"

# Build the SDK first (required - mkdocstrings needs to import the package)
maturin develop

# Serve docs locally with hot-reload at http://127.0.0.1:8000
mkdocs serve

# Or build static site to site/ directory
mkdocs build
```

The documentation uses [MkDocs](https://www.mkdocs.org/) with the [mkdocstrings](https://mkdocstrings.github.io/) plugin to auto-generate API docs from Python docstrings and type hints.

## License

This project is licensed under the Business Source License 1.1. See the [LICENSE](./LICENSE) file for details.
