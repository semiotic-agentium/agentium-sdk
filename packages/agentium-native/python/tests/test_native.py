# SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
#
# SPDX-License-Identifier: MIT

"""Tests for native Rust bindings."""

import base64
import json

import pytest

import agentium_sdk
from agentium_sdk import (
    GeneratedKeyPair,
    JwtHeader,
    VerificationResult,
    extract_public_key_jwk,
    generate_keypair,
    get_public_key,
    parse_jwt_header,
    verify_jwt,
)


class TestGenerateKeypair:
    """Tests for generate_keypair function."""

    def test_generates_keypair(self) -> None:
        """Should generate a valid Ed25519 keypair."""
        kp = generate_keypair()

        assert isinstance(kp, GeneratedKeyPair)
        assert kp.private_key_jwk
        assert kp.public_key_jwk

    def test_keypair_is_valid_jwk(self) -> None:
        """Generated keys should be valid JWK JSON."""
        kp = generate_keypair()

        private = json.loads(kp.private_key_jwk)
        public = json.loads(kp.public_key_jwk)

        # Ed25519 keys use OKP (Octet Key Pair)
        assert public["kty"] == "OKP"
        assert public["crv"] == "Ed25519"
        assert "x" in public  # Public key material

        # Private key should NOT be in public JWK
        assert "d" not in public

    def test_each_keypair_is_unique(self) -> None:
        """Each call should generate a different keypair."""
        kp1 = generate_keypair()
        kp2 = generate_keypair()

        assert kp1.public_key_jwk != kp2.public_key_jwk


class TestGetPublicKey:
    """Tests for get_public_key function."""

    def test_extracts_public_from_private(self) -> None:
        """Should extract public key from private key."""
        kp = generate_keypair()
        # private_key_jwk contains the whole KeyPair, extract just the private key
        keypair_data = json.loads(kp.private_key_jwk)
        private_jwk = json.dumps(keypair_data["private_key"])
        extracted = get_public_key(private_jwk)

        # Should match the originally generated public key
        assert json.loads(extracted) == json.loads(kp.public_key_jwk)

    def test_invalid_private_key_raises(self) -> None:
        """Should raise ValueError for invalid input."""
        with pytest.raises(ValueError):
            get_public_key("not-valid-json")

        with pytest.raises(ValueError):
            get_public_key('{"kty": "invalid"}')


class TestParseJwtHeader:
    """Tests for parse_jwt_header function."""

    def _make_jwt(self, header: dict, payload: dict = {"sub": "test"}) -> str:
        """Helper to create a minimal JWT."""
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        s = base64.urlsafe_b64encode(b"x" * 64).rstrip(b"=").decode()
        return f"{h}.{p}.{s}"

    def test_parses_header(self) -> None:
        """Should parse JWT header correctly."""
        jwt = self._make_jwt({"alg": "EdDSA", "typ": "JWT", "kid": "key-1"})
        header = parse_jwt_header(jwt)

        assert isinstance(header, JwtHeader)
        assert header.alg == "EdDSA"
        assert header.typ == "JWT"
        assert header.kid == "key-1"

    def test_optional_fields(self) -> None:
        """typ and kid are optional."""
        jwt = self._make_jwt({"alg": "EdDSA"})
        header = parse_jwt_header(jwt)

        assert header.alg == "EdDSA"
        assert header.typ is None
        assert header.kid is None

    def test_invalid_jwt_raises(self) -> None:
        """Should raise ValueError for invalid JWT."""
        with pytest.raises(ValueError):
            parse_jwt_header("not.a.valid.jwt.too.many.parts")

        with pytest.raises(ValueError):
            parse_jwt_header("only-one-part")

        with pytest.raises(ValueError):
            parse_jwt_header("")


class TestVerifyJwt:
    """Tests for verify_jwt function."""

    def test_verification_result_structure(self) -> None:
        """VerificationResult should have correct structure."""
        # Create a fake JWT that will fail verification
        h = base64.urlsafe_b64encode(b'{"alg":"EdDSA"}').rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode()
        s = base64.urlsafe_b64encode(b"x" * 64).rstrip(b"=").decode()
        fake_jwt = f"{h}.{p}.{s}"

        kp = generate_keypair()
        result = verify_jwt(fake_jwt, kp.public_key_jwk)

        assert isinstance(result, VerificationResult)
        assert result.valid is False
        assert result.claims is None
        assert result.error is not None
        assert result.error.code == "VERIFICATION_FAILED"

    def test_invalid_public_key_returns_error(self) -> None:
        """Should return error result for invalid public key."""
        h = base64.urlsafe_b64encode(b'{"alg":"EdDSA"}').rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=").decode()
        s = base64.urlsafe_b64encode(b"x" * 64).rstrip(b"=").decode()
        fake_jwt = f"{h}.{p}.{s}"

        result = verify_jwt(fake_jwt, "not-valid-json")

        assert result.valid is False
        assert result.error is not None


class TestExtractPublicKeyJwk:
    """Tests for extract_public_key_jwk function."""

    def _make_did_document(self, key_id: str = "key-1") -> str:
        """Helper to create a DID document."""
        kp = generate_keypair()
        public_jwk = json.loads(kp.public_key_jwk)

        doc = {
            "id": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": f"did:web:example.com#{key_id}",
                    "type": "JsonWebKey2020",
                    "controller": "did:web:example.com",
                    "publicKeyJwk": public_jwk,
                }
            ],
        }
        return json.dumps(doc)

    def test_extracts_first_key_without_kid(self) -> None:
        """Should extract first key when no kid provided."""
        doc = self._make_did_document()
        jwk = extract_public_key_jwk(doc)

        parsed = json.loads(jwk)
        assert parsed["kty"] == "OKP"
        assert parsed["crv"] == "Ed25519"

    def test_extracts_key_by_kid(self) -> None:
        """Should find key by kid."""
        doc = self._make_did_document("my-key")
        jwk = extract_public_key_jwk(doc, "my-key")

        parsed = json.loads(jwk)
        assert parsed["kty"] == "OKP"

    def test_invalid_kid_raises(self) -> None:
        """Should raise ValueError for unknown kid."""
        doc = self._make_did_document("key-1")

        with pytest.raises(ValueError, match="No public key found"):
            extract_public_key_jwk(doc, "unknown-key")

    def test_invalid_document_raises(self) -> None:
        """Should raise ValueError for invalid DID document."""
        with pytest.raises(ValueError):
            extract_public_key_jwk("not-valid-json")

        with pytest.raises(ValueError):
            extract_public_key_jwk('{"id": "did:web:x", "verificationMethod": []}')
