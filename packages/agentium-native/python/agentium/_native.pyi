# SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
#
# SPDX-License-Identifier: MIT

"""Type stubs for the native Rust extension module."""

from typing import Any

class VerificationError:
    """Structured error for verification failures."""

    code: str
    """Error code (e.g., "JWT_EXPIRED", "VERIFICATION_FAILED")"""

    message: str
    """Human-readable error message"""

class VerificationResult:
    """Result of JWT verification."""

    valid: bool
    """Whether the JWT signature is valid"""

    claims: str | None
    """JWT claims as JSON string if valid"""

    error: VerificationError | None
    """Structured error if invalid"""

    def claims_dict(self) -> dict[str, Any] | None:
        """Parse claims JSON into a Python dict.

        Returns:
            Parsed claims as dict, or None if verification failed.
        """
        ...

class JwtHeader:
    """Parsed JWT header."""

    alg: str
    """Algorithm (e.g., "EdDSA")"""

    typ: str | None
    """Token type (usually "JWT")"""

    kid: str | None
    """Key ID - references verification method in DID document"""

class GeneratedKeyPair:
    """Generated key pair with private and public keys."""

    private_key_jwk: str
    """Private key as JWK JSON string (keep secret!)"""

    public_key_jwk: str
    """Public key as JWK JSON string (safe to share)"""

def verify_jwt(jwt: str, public_key_jwk: str) -> VerificationResult:
    """Verify a JWT against a public key.

    Args:
        jwt: The JWT string to verify (compact format: header.payload.signature)
        public_key_jwk: The public key as JWK JSON string

    Returns:
        VerificationResult with validity status and decoded claims if valid
    """
    ...

def parse_jwt_header(jwt: str) -> JwtHeader:
    """Parse a JWT header without verifying the signature.

    Args:
        jwt: The JWT string (compact format: header.payload.signature)

    Returns:
        JwtHeader containing algorithm, type, and optional key ID

    Raises:
        ValueError: If the JWT format is invalid
    """
    ...

def extract_public_key_jwk(did_document_json: str, kid: str | None = None) -> str:
    """Extract the public key JWK from a DID document.

    Args:
        did_document_json: The DID document as JSON string
        kid: Optional key ID to match (from JWT header). Can be full ID or just fragment.

    Returns:
        The public key as JWK JSON string

    Raises:
        ValueError: If the DID document is invalid or no matching key is found
    """
    ...

def generate_keypair() -> GeneratedKeyPair:
    """Generate a new Ed25519 key pair.

    Returns:
        GeneratedKeyPair with private_key_jwk and public_key_jwk as JSON strings.
        The private key should be stored securely and never exposed.

    Raises:
        ValueError: If key generation fails
    """
    ...

def get_public_key(private_key_jwk: str) -> str:
    """Extract public key from a private JWK.

    Args:
        private_key_jwk: The private key as JWK JSON string

    Returns:
        The public key as JWK JSON string

    Raises:
        ValueError: If the private key is invalid
    """
    ...

def init_tracing(callback: Any, filter: str | None = None) -> None:
    """Initialize telemetry with a Python callback.

    Sets up tracing to forward log events to a Python function. This can only be
    called once per process; subsequent calls are ignored.

    Args:
        callback: Python function to receive telemetry events.
                  Each event has: kind, level, target, name, fields, ts_ms
        filter: Optional filter string (e.g., "info", "debug", "agentium=trace").
                Defaults to "info" if not provided.

    Example:
        >>> def my_handler(event):
        ...     print(f"[{event['level']}] {event['target']}: {event['fields']}")
        >>> init_tracing(my_handler, "debug")
    """
    ...
