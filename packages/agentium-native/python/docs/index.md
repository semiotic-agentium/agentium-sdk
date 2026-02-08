<!--
SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.

SPDX-License-Identifier: BUSL-1.1
-->


# Agentium Python SDK

Python SDK for Agentium Network - DID and Verifiable Credentials.

## Features

- **Google Sign-In Integration** - Connect identities with a single function call
- **Wallet Sign-In (SIWE)** - Authenticate with blockchain wallets via EIP-4361
- **Async-first Design** - Built with `httpx` for modern async Python
- **Native Rust Core** - Cryptographic operations powered by Rust via PyO3
- **Type Safety** - Full type hints and PEP 561 compatible

## Quick Example

### Google Sign-In

```python
import agentium_sdk

# Async (recommended)
wallet_address, did = await agentium_sdk.connect_google(google_id_token)

# Sync wrapper available
wallet_address, did = agentium_sdk.connect_google_sync(google_id_token)
```

### Wallet Sign-In

```python
import agentium_sdk

# Authenticate with wallet (SIWE/EIP-4361)
# Uses Base mainnet (eip155:8453) by default
wallet_address, did = await agentium_sdk.connect_wallet(
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
    private_key="ac0974bfc...",
)

# Or specify testnet explicitly
from agentium_sdk import Caip2

wallet_address, did = await agentium_sdk.connect_wallet(
    address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
    private_key="ac0974bfc...",
    chain_id=Caip2.BASE_SEPOLIA,  # or "eip155:84532" for testnet
)

# Sync wrapper available
wallet_address, did = agentium_sdk.connect_wallet_sync(address, private_key)
```

## Installation

```bash
pip install agentium-sdk
```

## Next Steps

- [Getting Started](getting-started.md) - Installation and first steps
- [API Reference](api/index.md) - Complete API documentation
