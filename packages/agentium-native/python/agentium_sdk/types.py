# SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
#
# SPDX-License-Identifier: MIT

"""Type definitions for Agentium SDK responses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

__all__ = [
    "GrantType",
    "OAuthTokenResponse",
    "Badge",
    "ConnectIdentityResponse",
    "CredentialResponse",
    "WalletChallengeResponse",
]

# Grant types supported by the OAuth endpoint
GrantType = Literal[
    "api_key",
    "refresh_token",
    "google_id_token",
]


@dataclass(frozen=True)
class OAuthTokenResponse:
    """OAuth 2.0 token response from the backend."""

    access_token: str
    """JWT access token for authenticated API calls."""

    refresh_token: str
    """JWT refresh token for obtaining new access tokens."""

    token_type: str
    """Token type (always "Bearer")."""

    expires_in: int
    """Token expiration time in seconds."""

    scope: str
    """Space-separated scope string containing user info and DID.
    Format: "user did:pkh:eip155:1:0x... [new_user]"
    """


@dataclass(frozen=True)
class Badge:
    """Represents the status of a user's badge."""

    status: str


@dataclass(frozen=True)
class ConnectIdentityResponse:
    """Response from a successful connect identity call."""

    did: str
    """The user's Decentralized Identifier (DID)."""

    badge: Badge
    """Information about the user's badge status."""

    is_new: bool
    """Whether this is a newly created identity."""

    access_token: str
    """JWT access token for authenticated API calls."""

    refresh_token: str
    """JWT refresh token for obtaining new access tokens."""

    expires_in: int
    """Token expiration time in seconds."""


@dataclass(frozen=True)
class CredentialResponse:
    """Response from credential fetch endpoint."""

    credential: str
    """The JWT-encoded Verifiable Credential."""


@dataclass(frozen=True)
class WalletChallengeResponse:
    """Response from wallet challenge request."""

    message: str
    """The challenge message to sign (format is chain-specific)."""

    nonce: str
    """Unique nonce for replay protection."""


def _parse_scope_for_identity(scope: str) -> tuple[str, bool]:
    """Parse OAuth scope string to extract DID and new_user flag.

    Scope format: "user did:pkh:eip155:1:0x... [new_user]"

    Args:
        scope: The scope string from OAuth response.

    Returns:
        Tuple of (did, is_new).
    """
    parts = scope.split()
    did = next((part for part in parts if part.startswith("did:pkh:")), "")
    is_new = "new_user" in parts
    return did, is_new
