# SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
#
# SPDX-License-Identifier: MIT

"""Tests for types and utility functions."""

import pytest

from agentium import _extract_wallet_address
from agentium.types import (
    Badge,
    ConnectIdentityResponse,
    OAuthTokenResponse,
    parse_scope_for_identity,
)


class TestParseScopeForIdentity:
    """Tests for parse_scope_for_identity function."""

    def test_extracts_did_and_new_user(self) -> None:
        """Should extract DID and detect new_user flag."""
        scope = "user did:pkh:eip155:1:0xAbC123 new_user"
        did, is_new = parse_scope_for_identity(scope)

        assert did == "did:pkh:eip155:1:0xAbC123"
        assert is_new is True

    def test_existing_user(self) -> None:
        """Should detect existing user (no new_user flag)."""
        scope = "user did:pkh:eip155:1:0xAbC123"
        did, is_new = parse_scope_for_identity(scope)

        assert did == "did:pkh:eip155:1:0xAbC123"
        assert is_new is False

    def test_empty_scope(self) -> None:
        """Should handle empty scope gracefully."""
        did, is_new = parse_scope_for_identity("")

        assert did == ""
        assert is_new is False

    def test_no_did_in_scope(self) -> None:
        """Should return empty DID if not present."""
        scope = "user some_other_scope"
        did, is_new = parse_scope_for_identity(scope)

        assert did == ""
        assert is_new is False


class TestExtractWalletAddress:
    """Tests for _extract_wallet_address function."""

    def test_extracts_address_from_pkh_did(self) -> None:
        """Should extract wallet address from did:pkh DID."""
        did = "did:pkh:eip155:1:0xAbC123def456789"
        wallet = _extract_wallet_address(did)

        assert wallet == "0xAbC123def456789"

    def test_different_chain_id(self) -> None:
        """Should work with different chain IDs."""
        # Base mainnet (chain ID 8453)
        did = "did:pkh:eip155:8453:0x1234567890abcdef"
        wallet = _extract_wallet_address(did)

        assert wallet == "0x1234567890abcdef"

    def test_non_pkh_did_returns_empty(self) -> None:
        """Should return empty string for non-pkh DIDs."""
        assert _extract_wallet_address("did:web:example.com") == ""
        assert _extract_wallet_address("did:key:z6Mk...") == ""

    def test_invalid_did_returns_empty(self) -> None:
        """Should return empty string for invalid DIDs."""
        assert _extract_wallet_address("") == ""
        assert _extract_wallet_address("not-a-did") == ""
        assert _extract_wallet_address("did:pkh:eip155:1") == ""  # Missing address


class TestDataclasses:
    """Tests for dataclass structures."""

    def test_oauth_token_response(self) -> None:
        """OAuthTokenResponse should be immutable."""
        response = OAuthTokenResponse(
            access_token="access",
            refresh_token="refresh",
            token_type="Bearer",
            expires_in=3600,
            scope="user did:pkh:eip155:1:0x123",
        )

        assert response.access_token == "access"
        assert response.token_type == "Bearer"

        # Should be frozen (immutable)
        with pytest.raises(AttributeError):
            response.access_token = "new"  # type: ignore

    def test_connect_identity_response(self) -> None:
        """ConnectIdentityResponse should have all required fields."""
        response = ConnectIdentityResponse(
            did="did:pkh:eip155:1:0x123",
            badge=Badge(status="Active"),
            is_new=True,
            access_token="access",
            refresh_token="refresh",
            expires_in=3600,
        )

        assert response.did == "did:pkh:eip155:1:0x123"
        assert response.badge.status == "Active"
        assert response.is_new is True
