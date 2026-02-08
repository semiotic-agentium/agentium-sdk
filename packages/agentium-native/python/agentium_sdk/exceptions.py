# SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
#
# SPDX-License-Identifier: BUSL-1.1

"""Exception types for Agentium SDK."""

from __future__ import annotations


class AgentiumApiError(Exception):
    """Custom error class for API-related errors from the AgentiumClient.

    Attributes:
        message: Human-readable error message.
        status_code: HTTP status code if available.
    """

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def __str__(self) -> str:
        if self.status_code:
            return f"{self.message} (HTTP {self.status_code})"
        return self.message

    def __repr__(self) -> str:
        if self.status_code:
            return f"AgentiumApiError({self.message!r}, status_code={self.status_code})"
        return f"AgentiumApiError({self.message!r})"
