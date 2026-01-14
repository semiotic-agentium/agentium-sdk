<!-- SPDX-FileCopyrightText: 2025 Semiotic AI, Inc. -->
<!-- SPDX-License-Identifier: MIT -->

# Getting Started

## Installation

```bash
pip install agentium-sdk
```

## Basic Usage

### Connect with Google Sign-In

The simplest way to use Agentium is through the `connect_google` function:

```python
import agentium_sdk

async def handle_google_login(google_id_token: str):
    """Handle Google Sign-In and get wallet address + DID."""
    wallet_address, did = await agentium_sdk.connect_google(google_id_token)
    
    print(f"Wallet: {wallet_address}")  # 0x...
    print(f"DID: {did}")                # did:pkh:eip155:1:0x...
    
    return wallet_address, did
```

For synchronous code:

```python
wallet_address, did = agentium_sdk.connect_google_sync(google_id_token)
```

### Wallet Authentication

Authenticate using a blockchain wallet:

```python
import agentium_sdk

async def handle_wallet_login(address: str, chain_id: str, private_key: bytes):
    """Authenticate with wallet and get DID."""
    # chain_id is in CAIP-2 format (e.g., "eip155:84532")
    wallet_address, did = await agentium_sdk.connect_wallet(
        address, chain_id, private_key
    )
    
    print(f"Connected wallet: {wallet_address}")
    print(f"DID: {did}")
```

For synchronous code:

```python
wallet, did = agentium_sdk.connect_wallet_sync(address, chain_id, private_key)
```

### Using AgentiumClient

For more control, use the `AgentiumClient` directly. By default, it connects to `https://api.agentium.network`. You can override this with `AgentiumClient(base_url="https://your.endpoint")`.

#### Google Sign-In with Client

```python
from agentium_sdk import AgentiumClient

async with AgentiumClient() as client:
    # Connect identity
    response = await client.connect_google_identity(google_id_token)
    
    # Fetch membership credential
    credential = await client.fetch_membership_credential(response.access_token)
    
    # Verify credential
    result = await client.verify_credential(credential)
    if result.valid:
        print(result.claims)  # dict with JWT claims
```

#### Wallet Sign-In with Client

The client provides three wallet authentication methods:

**Option 1: Full flow with local signing (recommended)**

```python
from agentium_sdk import AgentiumClient

async with AgentiumClient() as client:
    # Complete wallet sign-in in one call
    response = await client.connect_wallet(
        address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
        chain_id="eip155:84532",  # CAIP-2 format (Base Sepolia)
        private_key="ac0974bfc...",  # hex string or bytes
    )
    
    print(response.did)           # did:pkh:eip155:84532:0x...
    print(response.access_token)  # JWT for authenticated calls
    print(response.is_new)        # True if first time
```

**Option 2: Manual challenge-response flow**

Useful when signing happens externally (e.g., browser wallet like MetaMask):

```python
from agentium_sdk import AgentiumClient

async with AgentiumClient() as client:
    # 1. Request challenge
    challenge = await client.request_wallet_challenge(
        address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
        chain_id="eip155:84532",
    )
    print(challenge.message)  # SIWE message to sign
    print(challenge.nonce)    # Unique nonce
    
    # 2. Sign externally (e.g., with MetaMask via personal_sign)
    signature = "0x..."  # Get signature from wallet
    
    # 3. Verify and get tokens
    tokens = await client.verify_wallet_signature(challenge.message, signature)
    print(tokens.access_token)
    print(tokens.refresh_token)
```

## Telemetry

Enable structured tracing for debugging:

```python
from agentium_sdk import init_tracing

def handle_event(event: dict):
    print(f"[{event['level']}] {event['name']}: {event['fields']}")

# Initialize once at startup
init_tracing(handle_event, "debug")
```

## Error Handling

```python
from agentium_sdk import AgentiumClient, AgentiumApiError

async with AgentiumClient() as client:
    try:
        response = await client.connect_google_identity(invalid_token)
    except AgentiumApiError as e:
        print(f"Error: {e.message}")
        print(f"Status: {e.status_code}")
```

## Next Steps

- [API Reference](api/index.md) - Complete API documentation
- [Client Methods](api/client.md) - All AgentiumClient methods
- [Native Functions](api/native.md) - Low-level cryptographic operations
