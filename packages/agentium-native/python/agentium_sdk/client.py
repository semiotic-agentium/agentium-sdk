# SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
#
# SPDX-License-Identifier: MIT

"""Agentium API client for authentication and credential management."""

from __future__ import annotations

import json
from typing import Any

import httpx

from agentium_sdk._native import (
    VerificationResult,
    extract_public_key_jwk,
    parse_jwt_header,
    verify_jwt,
)
from agentium_sdk.exceptions import AgentiumApiError
from agentium_sdk.types import (
    Badge,
    ConnectIdentityResponse,
    GrantType,
    OAuthTokenResponse,
    WalletChallengeResponse,
    _parse_scope_for_identity,
)

DEFAULT_BASE_URL = "https://api.agentium.network"
OAUTH_TOKEN_PATH = "/oauth/token"
MEMBERSHIP_CREDENTIAL_PATH = "/v1/credentials/membership"
DID_DOCUMENT_PATH = "/.well-known/did.json"
WALLET_CHALLENGE_PATH = "/auth/wallet/challenge"
WALLET_VERIFY_PATH = "/auth/wallet/verify"


class AgentiumClient:
    """A client for interacting with the Agentium API.

    This client provides methods for:
    - Connecting Google identities to create DIDs
    - Exchanging API keys for tokens (M2M authentication)
    - Refreshing access tokens
    - Fetching and verifying membership credentials

    Example:
        >>> async with AgentiumClient() as client:
        ...     response = await client.connect_google_identity(google_id_token)
        ...     print(response.did)
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
    ) -> None:
        """Create an AgentiumClient instance.

        Args:
            base_url: The base URL of the Agentium API.
                Defaults to https://api.agentium.network
            timeout: Request timeout in seconds. Defaults to 30.0.
        """
        self._base_url = base_url
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=self._timeout,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client connection."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> AgentiumClient:
        """Async context manager entry."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        await self.close()

    async def _oauth_token_request(
        self, grant_type: GrantType, **kwargs: str
    ) -> OAuthTokenResponse:
        """Make an OAuth token request.

        Args:
            grant_type: The OAuth grant type.
            **kwargs: Additional parameters for the request body.

        Returns:
            OAuthTokenResponse with tokens and scope.

        Raises:
            AgentiumApiError: If the request fails.
        """
        client = await self._get_client()
        payload = {"grant_type": grant_type, **kwargs}

        try:
            response = await client.post(OAUTH_TOKEN_PATH, json=payload)
            response.raise_for_status()
            data = response.json()
            return OAuthTokenResponse(
                access_token=data["access_token"],
                refresh_token=data["refresh_token"],
                token_type=data["token_type"],
                expires_in=data["expires_in"],
                scope=data["scope"],
            )
        except httpx.HTTPStatusError as e:
            raise AgentiumApiError(str(e), e.response.status_code) from e
        except httpx.RequestError as e:
            raise AgentiumApiError(str(e)) from e

    async def connect_google_identity(self, google_token: str) -> ConnectIdentityResponse:
        """Connect a Google identity to an Agentium identity.

        Args:
            google_token: The JWT token obtained from Google Sign-In.

        Returns:
            ConnectIdentityResponse containing the user's DID and tokens.

        Raises:
            AgentiumApiError: If the request fails.
                - 400: Bad Request - malformed request or unsupported grant type.
                - 401: Unauthorized - invalid or expired JWT token.
                - 500: Internal Server Error.
        """
        token_response = await self._oauth_token_request("google_id_token", id_token=google_token)

        did, is_new = _parse_scope_for_identity(token_response.scope)

        return ConnectIdentityResponse(
            did=did,
            badge=Badge(status="Active" if is_new else "Existing"),
            is_new=is_new,
            access_token=token_response.access_token,
            refresh_token=token_response.refresh_token,
            expires_in=token_response.expires_in,
        )

    async def exchange_api_key(self, api_key: str) -> OAuthTokenResponse:
        """Exchange an API key for JWT tokens (M2M authentication).

        Args:
            api_key: The API key to exchange.

        Returns:
            OAuthTokenResponse with access and refresh tokens.

        Raises:
            AgentiumApiError: If the request fails.
        """
        return await self._oauth_token_request("api_key", api_key=api_key)

    async def refresh_token(self, refresh_token_value: str) -> OAuthTokenResponse:
        """Refresh an access token using a refresh token.

        Args:
            refresh_token_value: The refresh token to use.

        Returns:
            OAuthTokenResponse with new access and refresh tokens.

        Raises:
            AgentiumApiError: If the request fails.
        """
        return await self._oauth_token_request("refresh_token", refresh_token=refresh_token_value)

    async def fetch_membership_credential(self, token: str) -> str:
        """Fetch a membership credential from the backend.

        Args:
            token: An auth token for authorization.

        Returns:
            Raw JWT string containing the credential.

        Raises:
            AgentiumApiError: 401 if token invalid/expired, 403 if user banned.
        """
        client = await self._get_client()

        try:
            response = await client.post(
                MEMBERSHIP_CREDENTIAL_PATH,
                json={},
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
            data = response.json()

            credential = data.get("credential")
            if not credential:
                raise AgentiumApiError("No credential in response from server")
            return credential
        except httpx.HTTPStatusError as e:
            raise AgentiumApiError(str(e), e.response.status_code) from e
        except httpx.RequestError as e:
            raise AgentiumApiError(str(e)) from e

    async def fetch_issuer_did_document(self) -> dict[str, Any]:
        """Fetch the issuer's DID document from /.well-known/did.json.

        The DID document contains the public key used to verify VCs.

        Returns:
            The issuer's DID document as a dict.

        Raises:
            AgentiumApiError: If the request fails.
        """
        client = await self._get_client()

        try:
            response = await client.get(DID_DOCUMENT_PATH)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise AgentiumApiError(str(e), e.response.status_code) from e
        except httpx.RequestError as e:
            raise AgentiumApiError(str(e)) from e

    async def verify_credential(self, jwt: str) -> VerificationResult:
        """Verify a JWT-VC against the issuer's public key.

        Extracts the key ID from the JWT header, fetches the DID document,
        finds the matching public key, and verifies the signature.

        Args:
            jwt: The JWT-VC to verify.

        Returns:
            VerificationResult with validity status, decoded claims, and error if invalid.
        """
        # Extract kid from JWT header to find the correct key
        header = parse_jwt_header(jwt)
        did_document = await self.fetch_issuer_did_document()
        did_document_json = json.dumps(did_document)
        public_key_jwk = extract_public_key_jwk(did_document_json, header.kid)

        return verify_jwt(jwt, public_key_jwk)

    async def request_wallet_challenge(
        self, address: str, chain_id: str
    ) -> WalletChallengeResponse:
        """Request a challenge message for wallet sign-in.

        Args:
            address: Wallet address (format is chain-specific, 0x-prefixed for EVM).
            chain_id: CAIP-2 chain identifier (e.g., "eip155:84532").
                See: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md

        Returns:
            WalletChallengeResponse with message to sign and nonce.

        Raises:
            AgentiumApiError: If chain not supported or request fails.
        """
        client = await self._get_client()

        try:
            response = await client.get(
                WALLET_CHALLENGE_PATH,
                params={"address": address, "chain_id": chain_id},
            )
            response.raise_for_status()
            data = response.json()
            return WalletChallengeResponse(
                message=data["message"],
                nonce=data["nonce"],
            )
        except httpx.HTTPStatusError as e:
            raise AgentiumApiError(str(e), e.response.status_code) from e
        except httpx.RequestError as e:
            raise AgentiumApiError(str(e)) from e

    async def verify_wallet_signature(self, message: str, signature: str) -> OAuthTokenResponse:
        """Verify wallet signature and obtain tokens.

        Args:
            message: The challenge message that was signed.
            signature: Hex-encoded signature (format is chain-specific).

        Returns:
            OAuthTokenResponse with access and refresh tokens.

        Raises:
            AgentiumApiError: If signature invalid or verification fails.
        """
        client = await self._get_client()

        try:
            response = await client.post(
                WALLET_VERIFY_PATH,
                json={"message": message, "signature": signature},
            )
            response.raise_for_status()
            data = response.json()
            return OAuthTokenResponse(
                access_token=data["access_token"],
                refresh_token=data["refresh_token"],
                token_type=data["token_type"],
                expires_in=data["expires_in"],
                scope=data["scope"],
            )
        except httpx.HTTPStatusError as e:
            raise AgentiumApiError(str(e), e.response.status_code) from e
        except httpx.RequestError as e:
            raise AgentiumApiError(str(e)) from e


async def connect_wallet(
    self,
    address: str,
    chain_id: str,
    private_key: bytes | str,
) -> ConnectIdentityResponse:
    """Connect a wallet identity using local signing.

    This method handles the full wallet sign-in flow:
    1. Request challenge from backend
    2. Sign challenge with private key (locally)
    3. Submit signature for verification
    4. Return identity response with tokens

    Args:
        address: Wallet address (format is chain-specific).
        chain_id: CAIP-2 chain identifier (e.g., "eip155:84532").
            See: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md
        private_key: Raw private key bytes or hex string (with or without 0x prefix).

    Returns:
        ConnectIdentityResponse with DID and tokens.

    Raises:
        AgentiumApiError: If any API step fails.
        ValueError: If signing fails (invalid key, unsupported chain).

    Example:
        >>> async with AgentiumClient() as client:
        ...     response = await client.connect_wallet(
        ...         address="0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b7",
        ...         chain_id="eip155:84532",
        ...         private_key="ac0974...",  # hex string or bytes
        ...     )
        ...     print(response.did)
    """
    from agentium_sdk._native import sign_challenge

    # Normalize private key to bytes
    if isinstance(private_key, str):
        private_key = bytes.fromhex(private_key.removeprefix("0x"))

    # 1. Get challenge
    challenge = await self.request_wallet_challenge(address, chain_id)

    # 2. Sign locally
    signature = sign_challenge(
        challenge.message.encode("utf-8"),
        chain_id,
        private_key,
    )

    # 3. Verify and get tokens
    token_response = await self.verify_wallet_signature(challenge.message, signature)

    # 4. Parse identity from scope
    did, is_new = _parse_scope_for_identity(token_response.scope)

    return ConnectIdentityResponse(
        did=did,
        badge=Badge(status="Active" if is_new else "Existing"),
        is_new=is_new,
        access_token=token_response.access_token,
        refresh_token=token_response.refresh_token,
        expires_in=token_response.expires_in,
    )
