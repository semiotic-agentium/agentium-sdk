# SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
#
# SPDX-License-Identifier: BUSL-1.1

"""Tests for AgentiumClient with mocked HTTP responses."""

import httpx
import pytest
import respx

from agentium_sdk import AgentiumApiError, AgentiumClient, connect_google, connect_wallet


@pytest.fixture
def mock_oauth_response() -> dict:
    """Standard OAuth token response."""
    return {
        "access_token": "test-access-token",
        "refresh_token": "test-refresh-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "user did:pkh:eip155:1:0xAbC123def456 new_user",
    }


@pytest.fixture
def mock_did_document() -> dict:
    """Standard DID document response."""
    return {
        "id": "did:web:api.agentium.network",
        "verificationMethod": [
            {
                "id": "did:web:api.agentium.network#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:web:api.agentium.network",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "test-public-key-x",
                },
            }
        ],
    }


class TestAgentiumClientConnectGoogle:
    """Tests for connect_google_identity method."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_google_identity_success(self, mock_oauth_response: dict) -> None:
        """Should successfully connect Google identity."""
        respx.post("https://api.agentium.network/oauth/token").mock(
            return_value=httpx.Response(200, json=mock_oauth_response)
        )

        async with AgentiumClient() as client:
            response = await client.connect_google_identity("fake-google-token")

        assert response.did == "did:pkh:eip155:1:0xAbC123def456"
        assert response.is_new is True
        assert response.access_token == "test-access-token"
        assert response.refresh_token == "test-refresh-token"
        assert response.badge.status == "Active"

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_google_identity_existing_user(self) -> None:
        """Should detect existing user."""
        respx.post("https://api.agentium.network/oauth/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "token",
                    "refresh_token": "refresh",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "user did:pkh:eip155:1:0x123",  # No new_user flag
                },
            )
        )

        async with AgentiumClient() as client:
            response = await client.connect_google_identity("fake-token")

        assert response.is_new is False
        assert response.badge.status == "Existing"

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_google_identity_unauthorized(self) -> None:
        """Should raise AgentiumApiError on 401."""
        respx.post("https://api.agentium.network/oauth/token").mock(
            return_value=httpx.Response(401, json={"error": "invalid_token"})
        )

        async with AgentiumClient() as client:
            with pytest.raises(AgentiumApiError) as exc_info:
                await client.connect_google_identity("invalid-token")

        assert exc_info.value.status_code == 401


class TestAgentiumClientExchangeApiKey:
    """Tests for exchange_api_key method."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_exchange_api_key_success(self, mock_oauth_response: dict) -> None:
        """Should successfully exchange API key."""
        respx.post("https://api.agentium.network/oauth/token").mock(
            return_value=httpx.Response(200, json=mock_oauth_response)
        )

        async with AgentiumClient() as client:
            response = await client.exchange_api_key("test-api-key")

        assert response.access_token == "test-access-token"
        assert response.token_type == "Bearer"


class TestAgentiumClientRefreshToken:
    """Tests for refresh_token method."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_refresh_token_success(self, mock_oauth_response: dict) -> None:
        """Should successfully refresh token."""
        respx.post("https://api.agentium.network/oauth/token").mock(
            return_value=httpx.Response(200, json=mock_oauth_response)
        )

        async with AgentiumClient() as client:
            response = await client.refresh_token("old-refresh-token")

        assert response.access_token == "test-access-token"


class TestAgentiumClientFetchCredential:
    """Tests for fetch_membership_credential method."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_credential_success(self) -> None:
        """Should fetch membership credential."""
        respx.post("https://api.agentium.network/v1/credentials/membership").mock(
            return_value=httpx.Response(200, json={"credential": "jwt-credential"})
        )

        async with AgentiumClient() as client:
            credential = await client.fetch_membership_credential("auth-token")

        assert credential == "jwt-credential"

    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_credential_no_credential_in_response(self) -> None:
        """Should raise error if credential missing from response."""
        respx.post("https://api.agentium.network/v1/credentials/membership").mock(
            return_value=httpx.Response(200, json={})
        )

        async with AgentiumClient() as client:
            with pytest.raises(AgentiumApiError, match="No credential"):
                await client.fetch_membership_credential("auth-token")


class TestAgentiumClientFetchDidDocument:
    """Tests for fetch_issuer_did_document method."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_did_document_success(self, mock_did_document: dict) -> None:
        """Should fetch DID document."""
        respx.get("https://api.agentium.network/.well-known/did.json").mock(
            return_value=httpx.Response(200, json=mock_did_document)
        )

        async with AgentiumClient() as client:
            doc = await client.fetch_issuer_did_document()

        assert doc["id"] == "did:web:api.agentium.network"
        assert len(doc["verificationMethod"]) == 1


class TestTopLevelConnectGoogle:
    """Tests for top-level connect_google function."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_google_returns_wallet_and_did(self) -> None:
        """Should return tuple of (wallet_address, did)."""
        respx.post("https://api.agentium.network/oauth/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "token",
                    "refresh_token": "refresh",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "user did:pkh:eip155:1:0xAbC123def456789",
                },
            )
        )

        wallet_address, did = await connect_google("google-token")

        assert wallet_address == "0xAbC123def456789"
        assert did == "did:pkh:eip155:1:0xAbC123def456789"


class TestClientContextManager:
    """Tests for client context manager behavior."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_context_manager_closes_client(self) -> None:
        """Client should be closed after context manager exit."""
        respx.post("https://api.agentium.network/oauth/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "token",
                    "refresh_token": "refresh",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "user did:pkh:eip155:1:0x123",
                },
            )
        )

        client = AgentiumClient()
        async with client:
            await client.connect_google_identity("token")

        # Client should be closed
        assert client._client is None


class TestClientCustomBaseUrl:
    """Tests for custom base URL support."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_custom_base_url(self) -> None:
        """Should use custom base URL."""
        respx.post("https://custom.api.com/oauth/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "token",
                    "refresh_token": "refresh",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "user did:pkh:eip155:1:0x123",
                },
            )
        )

        async with AgentiumClient(base_url="https://custom.api.com") as client:
            response = await client.connect_google_identity("token")

        assert response.access_token == "token"


class TestWalletChallengeRequest:
    """Tests for wallet challenge request."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_request_wallet_challenge(self) -> None:
        """Test wallet challenge request."""
        respx.get("https://api.agentium.network/auth/wallet/challenge").mock(
            return_value=httpx.Response(
                200,
                json={
                    "message": "Challenge message from backend...",
                    "nonce": "abc123",
                },
            )
        )

        async with AgentiumClient() as client:
            challenge = await client.request_wallet_challenge(
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
                "eip155:84532",
            )

        assert challenge.nonce == "abc123"
        assert challenge.message == "Challenge message from backend..."

    @respx.mock
    @pytest.mark.asyncio
    async def test_request_wallet_challenge_error(self) -> None:
        """Test wallet challenge request error."""
        respx.get("https://api.agentium.network/auth/wallet/challenge").mock(
            return_value=httpx.Response(400, json={"error": "invalid_chain"})
        )

        async with AgentiumClient() as client:
            with pytest.raises(AgentiumApiError) as exc_info:
                await client.request_wallet_challenge("0x123", "invalid:chain")

        assert exc_info.value.status_code == 400


class TestWalletSignatureVerification:
    """Tests for wallet signature verification."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_verify_wallet_signature(self) -> None:
        """Test wallet signature verification."""
        respx.post("https://api.agentium.network/auth/wallet/verify").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "access_jwt",
                    "refresh_token": "refresh_jwt",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "user did:pkh:eip155:84532:0x742d... new_user",
                },
            )
        )

        async with AgentiumClient() as client:
            response = await client.verify_wallet_signature(
                "Challenge message...",
                "0xsignature...",
            )

        assert response.access_token == "access_jwt"
        assert "new_user" in response.scope

    @respx.mock
    @pytest.mark.asyncio
    async def test_verify_wallet_signature_invalid(self) -> None:
        """Test wallet signature verification with invalid signature."""
        respx.post("https://api.agentium.network/auth/wallet/verify").mock(
            return_value=httpx.Response(401, json={"error": "invalid_signature"})
        )

        async with AgentiumClient() as client:
            with pytest.raises(AgentiumApiError) as exc_info:
                await client.verify_wallet_signature("msg", "bad_sig")

        assert exc_info.value.status_code == 401


class TestConnectWallet:
    """Tests for connect_wallet method."""

    # Test private key (never use in production)
    TEST_PRIVATE_KEY = bytes.fromhex(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcbf5e9341ad332d3e"
    )
    TEST_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_wallet_full_flow(self) -> None:
        """Test full wallet connection flow."""
        # Mock challenge endpoint
        respx.get("https://api.agentium.network/auth/wallet/challenge").mock(
            return_value=httpx.Response(
                200,
                json={
                    "message": "Sign this message to authenticate",
                    "nonce": "nonce123",
                },
            )
        )

        # Mock verify endpoint
        respx.post("https://api.agentium.network/auth/wallet/verify").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "access_token",
                    "refresh_token": "refresh_token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": f"user did:pkh:eip155:84532:{self.TEST_ADDRESS} new_user",
                },
            )
        )

        async with AgentiumClient() as client:
            response = await client.connect_wallet(
                self.TEST_ADDRESS,
                self.TEST_PRIVATE_KEY,
                "eip155:84532",
            )

        assert response.did == f"did:pkh:eip155:84532:{self.TEST_ADDRESS}"
        assert response.is_new is True
        assert response.access_token == "access_token"
        assert response.refresh_token == "refresh_token"


class TestTopLevelConnectWallet:
    """Tests for top-level connect_wallet function."""

    TEST_PRIVATE_KEY = bytes.fromhex(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcbf5e9341ad332d3e"
    )
    TEST_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_wallet_returns_address_and_did(self) -> None:
        """Should return tuple of (wallet_address, did)."""
        respx.get("https://api.agentium.network/auth/wallet/challenge").mock(
            return_value=httpx.Response(
                200,
                json={"message": "Sign this", "nonce": "n123"},
            )
        )
        respx.post("https://api.agentium.network/auth/wallet/verify").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "token",
                    "refresh_token": "refresh",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": f"user did:pkh:eip155:84532:{self.TEST_ADDRESS}",
                },
            )
        )

        wallet_address, did = await connect_wallet(
            self.TEST_ADDRESS,
            self.TEST_PRIVATE_KEY,
            "eip155:84532",
        )

        assert wallet_address == self.TEST_ADDRESS
        assert did == f"did:pkh:eip155:84532:{self.TEST_ADDRESS}"
