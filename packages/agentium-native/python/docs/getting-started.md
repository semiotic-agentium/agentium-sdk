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
import agentium

async def handle_google_login(google_id_token: str):
    """Handle Google Sign-In and get wallet address + DID."""
    wallet_address, did = await agentium.connect_google(google_id_token)
    
    print(f"Wallet: {wallet_address}")  # 0x...
    print(f"DID: {did}")                # did:pkh:eip155:1:0x...
    
    return wallet_address, did
```

For synchronous code:

```python
wallet_address, did = agentium.connect_google_sync(google_id_token)
```

### Using AgentiumClient

For more control, use the `AgentiumClient` directly:

```python
from agentium import AgentiumClient

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

### Custom Endpoint

```python
async with AgentiumClient(base_url="https://custom.api.endpoint") as client:
    # ... use client
```

## Telemetry

Enable structured tracing for debugging:

```python
from agentium import init_tracing

def handle_event(event: dict):
    print(f"[{event['level']}] {event['name']}: {event['fields']}")

# Initialize once at startup
init_tracing(handle_event, "debug")
```

## Error Handling

```python
from agentium import AgentiumClient, AgentiumApiError

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
