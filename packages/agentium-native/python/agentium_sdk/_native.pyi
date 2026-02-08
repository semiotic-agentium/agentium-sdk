# SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
#
# SPDX-License-Identifier: BUSL-1.1

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

    claims: dict[str, Any] | None
    """JWT claims as Python dict if valid"""

    error: VerificationError | None
    """Structured error if invalid"""

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

def sign_challenge(message: bytes, chain_id: str, private_key: bytes) -> str:
    """Sign a challenge message for wallet authentication.

    The signing algorithm is determined by the chain namespace in the CAIP-2 identifier.
    For example, `eip155:*` chains use secp256k1 ECDSA with EIP-191 message encoding.

    Args:
        message: The challenge message bytes from the backend.
        chain_id: CAIP-2 chain identifier string (e.g., "eip155:84532").
            See: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md
        private_key: Raw private key bytes (format depends on chain, 32 bytes for EVM).

    Returns:
        Hex-encoded signature string (format is chain-specific).

    Raises:
        ValueError: If chain_id is not a valid CAIP-2 string, key is malformed,
            namespace is unsupported, or signing fails.
    """
    ...

def validate_caip2(chain_id: str) -> bool:
    """Validate a CAIP-2 chain identifier string.

    CAIP-2 defines a format for blockchain identifiers: `namespace:reference`
    - Namespace: 3-8 lowercase alphanumeric characters (e.g., "eip155", "solana")
    - Reference: 1-32 alphanumeric characters with hyphens/underscores (e.g., "1", "84532")

    See: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md

    Args:
        chain_id: String to validate (e.g., "eip155:84532", "cosmos:cosmoshub-4")

    Returns:
        True if valid, False otherwise. Never raises exceptions.
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
