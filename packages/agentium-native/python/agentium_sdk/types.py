# SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
#
# SPDX-License-Identifier: BUSL-1.1

"""Type definitions for Agentium SDK responses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Literal

__all__ = [
    "GrantType",
    "OAuthTokenResponse",
    "Badge",
    "ConnectIdentityResponse",
    "CredentialResponse",
    "WalletChallengeResponse",
    "Caip2",
    "Caip2Error",
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


class Caip2Error(ValueError):
    """Error raised when CAIP-2 parsing fails."""

    pass


@dataclass(frozen=True)
class Caip2:
    """CAIP-2 chain identifier (e.g., "eip155:84532", "eip155:1").

    CAIP-2 defines a format for blockchain identifiers: `namespace:reference`
    - Namespace: 3-8 lowercase alphanumeric characters (e.g., "eip155", "solana")
    - Reference: 1-32 alphanumeric characters with hyphens/underscores

    See: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md

    Pre-defined constants for supported chains:
        - `Caip2.BASE_SEPOLIA`: Base Sepolia testnet (eip155:84532)
        - `Caip2.BASE_MAINNET`: Base mainnet (eip155:8453)

    Example:
        >>> caip2 = Caip2.parse("eip155:84532")
        >>> caip2.namespace
        'eip155'
        >>> caip2.reference
        '84532'
        >>> caip2.evm_chain_id()
        84532
        >>> str(Caip2.BASE_SEPOLIA)
        'eip155:84532'
    """

    BASE_SEPOLIA: ClassVar[Caip2]
    """Base Sepolia testnet (chain ID 84532)."""

    BASE_MAINNET: ClassVar[Caip2]
    """Base mainnet (chain ID 8453)."""

    namespace: str
    """Chain namespace (e.g., "eip155", "solana", "cosmos")."""

    reference: str
    """Chain reference (e.g., "1", "84532", "cosmoshub-4")."""

    def __str__(self) -> str:
        """Return the CAIP-2 string representation."""
        return f"{self.namespace}:{self.reference}"

    @classmethod
    def parse(cls, chain_id: str) -> Caip2:
        """Parse a CAIP-2 string into a Caip2 object.

        Args:
            chain_id: CAIP-2 string (e.g., "eip155:84532")

        Returns:
            Parsed Caip2 object.

        Raises:
            Caip2Error: If the string is not valid CAIP-2 format.
        """
        if ":" not in chain_id:
            raise Caip2Error("CAIP-2 identifier must contain a colon separator")

        namespace, reference = chain_id.split(":", 1)

        # Validate namespace: 3-8 lowercase alphanumeric + hyphens
        if len(namespace) < 3:
            raise Caip2Error("namespace must be at least 3 characters")
        if len(namespace) > 8:
            raise Caip2Error("namespace must be at most 8 characters")
        if not all(c.islower() or c.isdigit() or c == "-" for c in namespace):
            raise Caip2Error(
                "namespace must contain only lowercase alphanumeric characters and hyphens"
            )

        # Validate reference: 1-32 alphanumeric + hyphens + underscores
        if len(reference) == 0:
            raise Caip2Error("reference cannot be empty")
        if len(reference) > 32:
            raise Caip2Error("reference must be at most 32 characters")
        if not all(c.isalnum() or c in "-_" for c in reference):
            raise Caip2Error(
                "reference must contain only alphanumeric characters, hyphens, and underscores"
            )

        return cls(namespace=namespace, reference=reference)

    def is_evm(self) -> bool:
        """Check if this is an EVM chain (eip155 namespace)."""
        return self.namespace == "eip155"

    def evm_chain_id(self) -> int:
        """Get the numeric EVM chain ID.

        Returns:
            The chain ID as an integer.

        Raises:
            Caip2Error: If not an EVM chain or reference is not numeric.
        """
        if not self.is_evm():
            raise Caip2Error(f"not an EVM chain: {self.namespace}")
        try:
            return int(self.reference)
        except ValueError:
            raise Caip2Error(f"chain reference is not numeric: {self.reference}")


# Pre-defined constants for supported chains
Caip2.BASE_SEPOLIA = Caip2(namespace="eip155", reference="84532")
Caip2.BASE_MAINNET = Caip2(namespace="eip155", reference="8453")


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
