# SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
#
# SPDX-License-Identifier: MIT

"""Agentium SDK for Python - DID and Verifiable Credentials.

This SDK provides authentication and identity management for Agentium Network.
It supports Google Sign-In integration, DID creation, and Verifiable Credential
verification.

Example:
    >>> import agentium_sdk
    >>> wallet_address, did = await agentium_sdk.connect_google(google_id_token)

"""

from __future__ import annotations

import asyncio

from agentium_sdk._native import (
    GeneratedKeyPair,
    JwtHeader,
    VerificationError,
    VerificationResult,
    extract_public_key_jwk,
    generate_keypair,
    get_public_key,
    init_tracing,
    parse_jwt_header,
    sign_challenge,
    validate_caip2,
    verify_jwt,
)
from agentium_sdk.client import AgentiumClient
from agentium_sdk.exceptions import AgentiumApiError
from agentium_sdk.types import (
    Badge,
    Caip2,
    Caip2Error,
    ConnectIdentityResponse,
    CredentialResponse,
    GrantType,
    OAuthTokenResponse,
    WalletChallengeResponse,
)

try:
    from importlib.metadata import version

    __version__ = version("agentium-sdk")
except Exception:
    __version__ = "0.0.0"  # Fallback for development


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
        >>> wallet_address, did = await agentium_sdk.connect_google(google_id_token)
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
        >>> wallet_address, did = agentium_sdk.connect_google_sync(google_id_token)
        >>> print(wallet_address)  # 0x...
        >>> print(did)  # did:pkh:eip155:1:0x...
    """
    return asyncio.run(connect_google(google_id_token, base_url=base_url))


async def connect_wallet(
    address: str,
    chain_id: str,
    private_key: bytes | str,
    *,
    base_url: str = "https://api.agentium.network",
) -> tuple[str, str]:
    """Connect a wallet identity and return wallet address and DID.

    Args:
        address: Wallet address (format is chain-specific).
        chain_id: CAIP-2 chain identifier (e.g., "eip155:84532").
            See: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md
        private_key: Raw private key bytes or hex string (with or without 0x prefix).
        base_url: The Agentium API base URL.

    Returns:
        Tuple of (wallet_address, did).

    Example:
        >>> wallet, did = await agentium_sdk.connect_wallet(
        ...     "0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
        ...     "eip155:84532",
        ...     "ac0974...",  # hex string or bytes
        ... )
    """
    async with AgentiumClient(base_url=base_url) as client:
        response = await client.connect_wallet(address, chain_id, private_key)
        return address, response.did


def connect_wallet_sync(
    address: str,
    chain_id: str,
    private_key: bytes | str,
    *,
    base_url: str = "https://api.agentium.network",
) -> tuple[str, str]:
    """Synchronous version of connect_wallet."""
    return asyncio.run(connect_wallet(address, chain_id, private_key, base_url=base_url))


__all__ = [
    # Top-level functions
    "connect_google",
    "connect_google_sync",
    "connect_wallet",
    "connect_wallet_sync",
    # Client
    "AgentiumClient",
    # Exceptions
    "AgentiumApiError",
    "Caip2Error",
    # Response types
    "ConnectIdentityResponse",
    "CredentialResponse",
    "OAuthTokenResponse",
    "WalletChallengeResponse",
    "Badge",
    "GrantType",
    # Types
    "Caip2",
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
    "sign_challenge",
    "validate_caip2",
]
