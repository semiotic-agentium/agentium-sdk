// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

//! Zero-copy JWT parsing utilities.
//!
//! This module provides a lightweight, zero-copy JWT parser that validates
//! structural correctness without requiring cryptographic verification.
//! It is designed for scenarios where JWT structure needs to be parsed
//! before signature verification is performed elsewhere.
//!
//! The parser validates that:
//! - The JWT has exactly three dot-separated parts
//! - Each part is valid base64url-encoded
//!
//! Claims deserialization is deferred and type-parameterized, allowing
//! callers to specify their expected claims structure.

use base64::Engine;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

/// JWT header structure.
///
/// Contains algorithm, token type, and optional key ID for
/// matching against verification methods in a DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    /// Algorithm (e.g., "EdDSA")
    pub alg: String,
    /// Token type (usually "JWT")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// Key ID - references verification method in DID document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// A zero-copy reference to a JWT string.
///
/// This type holds references to the original JWT string and its constituent
/// parts (header, payload, signature) without allocating new memory for them.
/// It validates JWT structure on construction but defers claims parsing
/// to the call site via [`JwtRef::claims`].
///
/// The JWT format is: `<header>.<payload>.<signature>` where each part
/// is base64url-encoded without padding.
pub struct JwtRef<'a> {
    /// The original raw JWT string.
    raw: &'a str,
    /// Base64url-encoded header portion.
    header: &'a str,
    /// Base64url-encoded payload portion.
    payload: &'a str,
    /// Base64url-encoded signature portion.
    signature: &'a str,
}

/// Errors that can occur during JWT parsing.
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Jwt must have exactly 3 dot-separated parts")]
    Parts,

    #[error("Invalid Base64url: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Could not deserialize claims: {0}")]
    InvalidClaims(#[from] serde_json::Error),
}

impl<'a> JwtRef<'a> {
    /// Parses a JWT string into its constituent parts.
    ///
    /// Validates that the JWT has exactly three dot-separated parts and that
    /// each part is valid base64url encoding. Does not validate claims content
    /// or perform cryptographic verification.
    fn from_str(raw: &'a str) -> Result<Self, JwtError> {
        let mut parts = raw.split('.');

        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            let e = JwtError::Parts;
            tracing::error!(error = %e, "Unexpected jwt format");
            return Err(e);
        };

        // Validate base64 encoding of all parts
        _ = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header_b64)?;
        _ = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64)?;
        _ = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signature_b64)?;

        Ok(Self {
            raw,
            header: header_b64,
            payload: payload_b64,
            signature: signature_b64,
        })
    }

    /// Returns the base64url-encoded header portion of the JWT.
    pub fn header(&self) -> &str {
        self.header
    }

    /// Returns the decoded header bytes.
    ///
    /// # Panics
    ///
    /// This method will not panic as the header was already validated
    /// during construction.
    pub fn header_bytes(&self) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.header)
            .expect("Decoded already")
    }

    /// Parses and returns the header from the JWT.
    ///
    /// The header is base64url-decoded and then deserialized from JSON
    /// into a [`JwtHeader`] containing algorithm, type, and key ID.
    pub fn header_claims(&self) -> Result<JwtHeader, JwtError> {
        let bytes = self.header_bytes();
        serde_json::from_slice(&bytes).map_err(JwtError::InvalidClaims)
    }

    /// Returns the base64url-encoded payload portion of the JWT.
    pub fn payload(&self) -> &str {
        self.payload
    }

    /// Returns the decoded payload bytes.
    ///
    /// # Panics
    ///
    /// This method will not panic as the payload was already validated
    /// during construction.
    pub fn payload_bytes(&self) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.payload)
            .expect("Decoded already")
    }

    /// Returns the base64url-encoded signature portion of the JWT.
    pub fn signature(&self) -> &str {
        self.signature
    }

    /// Returns the decoded signature bytes.
    ///
    /// # Panics
    ///
    /// This method will not panic as the signature was already validated
    /// during construction.
    pub fn signature_bytes(&self) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.signature)
            .expect("Decoded already")
    }

    /// Returns the signing input (`header.payload`) used for signature verification.
    ///
    /// This is the portion of the JWT that should be signed/verified,
    /// consisting of the base64url-encoded header and payload separated by a dot.
    pub fn signing_input(&self) -> &str {
        let header_len = self.header.len();
        let payload_len = self.payload.len();
        // +1 for the dot separator between header and payload
        let signing_input_len = header_len + 1 + payload_len;
        &self.raw[..signing_input_len]
    }

    /// Parses and returns the claims from the JWT payload.
    ///
    /// The caller specifies the expected claims type via the type parameter `C`.
    /// The payload is base64url-decoded and then deserialized from JSON.
    pub fn claims<C: DeserializeOwned>(&self) -> Result<C, JwtError> {
        let bytes = self.payload_bytes();
        serde_json::from_slice(&bytes).map_err(JwtError::InvalidClaims)
    }
}

impl<'a> TryFrom<&'a str> for JwtRef<'a> {
    type Error = JwtError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        JwtRef::from_str(value)
    }
}

impl<'a> TryFrom<&'a String> for JwtRef<'a> {
    type Error = JwtError;

    fn try_from(value: &'a String) -> Result<Self, Self::Error> {
        JwtRef::from_str(value)
    }
}
