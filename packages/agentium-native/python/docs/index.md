# Agentium Python SDK

Python SDK for Agentium Network - DID and Verifiable Credentials.

## Features

- **Google Sign-In Integration** - Connect identities with a single function call
- **Async-first Design** - Built with `httpx` for modern async Python
- **Native Rust Core** - Cryptographic operations powered by Rust via PyO3
- **Type Safety** - Full type hints and PEP 561 compatible

## Quick Example

```python
import agentium

# Async (recommended)
wallet_address, did = await agentium.connect_google(google_id_token)

# Sync wrapper available
wallet_address, did = agentium.connect_google_sync(google_id_token)
```

## Installation

```bash
pip install agentium-sdk
```

## Next Steps

- [Getting Started](getting-started.md) - Installation and first steps
- [API Reference](api/index.md) - Complete API documentation
