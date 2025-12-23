# SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
#
# SPDX-License-Identifier: MIT

"""Agentium SDK for Python - DID and Verifiable Credentials.

This SDK provides authentication and identity management for Agentium Network.
It supports Google Sign-In integration, DID creation, and Verifiable Credential
verification.

Example:
    >>> import agentium
    >>> wallet_address, did = await agentium.connect_google(google_id_token)

"""

from __future__ import annotations

import asyncio

from agentium._native import (
    GeneratedKeyPair,
    JwtHeader,
    VerificationError,
    VerificationResult,
    extract_public_key_jwk,
    generate_keypair,
    get_public_key,
    init_tracing,
    parse_jwt_header,
    verify_jwt,
)
from agentium.client import AgentiumClient
from agentium.exceptions import AgentiumApiError
from agentium.types import (
    Badge,
    ConnectIdentityResponse,
    GrantType,
    OAuthTokenResponse,
)

__version__ = "0.1.0"


def _extract_wallet_address(did: str) -> str:
    """Extract wallet address from a did:pkh DID.

    DID format: did:pkh:eip155:<chain_id>:<address>
    Example: did:pkh:eip155:1:0x1234... -> 0x1234...
    """
    if did.startswith("did:pkh:eip155:"):
        # Split by : and get the last part (address)
        parts = did.split(":")
        if len(parts) >= 5:
            return parts[4]
    return ""


async def connect_google(
    google_id_token: str,
    *,
    base_url: str = "https://api.agentium.network",
) -> tuple[str, str]:
    """Connect a Google identity and return wallet address and DID.

    This is a convenience function that creates a client, connects the identity,
    and returns the wallet address and DID.

    Args:
        google_id_token: The JWT token obtained from Google Sign-In.
        base_url: The Agentium API base URL.

    Returns:
        Tuple of (wallet_address, did).

    Raises:
        AgentiumApiError: If the request fails.

    Example:
        >>> wallet_address, did = await agentium.connect_google(google_id_token)
        >>> print(wallet_address)  # 0x...
        >>> print(did)  # did:pkh:eip155:1:0x...
    """
    async with AgentiumClient(base_url=base_url) as client:
        response = await client.connect_google_identity(google_id_token)
        wallet_address = _extract_wallet_address(response.did)
        return wallet_address, response.did


def connect_google_sync(
    google_id_token: str,
    *,
    base_url: str = "https://api.agentium.network",
) -> tuple[str, str]:
    """Synchronous version of connect_google.

    Args:
        google_id_token: The JWT token obtained from Google Sign-In.
        base_url: The Agentium API base URL.

    Returns:
        Tuple of (wallet_address, did).

    Raises:
        AgentiumApiError: If the request fails.

    Example:
        >>> wallet_address, did = agentium.connect_google_sync(google_id_token)
        >>> print(wallet_address)  # 0x...
        >>> print(did)  # did:pkh:eip155:1:0x...
    """
    return asyncio.run(connect_google(google_id_token, base_url=base_url))


__all__ = [
    # Top-level functions
    "connect_google",
    "connect_google_sync",
    # Client
    "AgentiumClient",
    # Exceptions
    "AgentiumApiError",
    # Response types
    "ConnectIdentityResponse",
    "OAuthTokenResponse",
    "Badge",
    "GrantType",
    # Native types
    "VerificationResult",
    "VerificationError",
    "JwtHeader",
    "GeneratedKeyPair",
    # Native functions
    "verify_jwt",
    "parse_jwt_header",
    "extract_public_key_jwk",
    "generate_keypair",
    "get_public_key",
    "init_tracing",
]
