// SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
//
// SPDX-License-Identifier: BUSL-1.1

//! DID (Decentralized Identifier) types and operations.
//!
//! This module provides strongly-typed representations for DIDs and DID Documents
//! as specified by W3C. It includes newtypes to prevent mixing up different
//! identifier types at compile time.
//!
//! Validation is performed using the `ssi` crate's DID parser which implements
//! the W3C DID Core specification.

use crate::VcError;
use serde::{Deserialize, Deserializer, Serialize};
use ssi::dids::{DID, DIDURL};
use std::fmt;
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur when parsing DID-related identifiers.
#[derive(Debug, Error, Clone)]
pub enum DidParseError {
    /// The string is not a valid DID per W3C DID Core specification.
    #[error("invalid DID `{value}`: {reason}")]
    InvalidDid { value: String, reason: String },

    /// The string is not a valid DID URL (KeyId) per W3C DID Core specification.
    #[error("invalid DID URL `{value}`: {reason}")]
    InvalidDidUrl { value: String, reason: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Newtypes for DID identifiers
// ─────────────────────────────────────────────────────────────────────────────

/// A Decentralized Identifier (DID).
///
/// DIDs are URIs that associate a subject with a DID document,
/// enabling verifiable, decentralized digital identity.
///
/// Format: `did:<method>:<method-specific-id>`
///
/// Examples:
/// - `did:web:api.agentium.network`
/// - `did:pkh:eip155:1:0x1234...`
///
/// Validation is performed using the `ssi` crate's W3C-compliant DID parser.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    /// Parses and validates a DID string.
    ///
    /// Uses the `ssi` crate's W3C-compliant DID parser for validation.
    ///
    /// # Errors
    ///
    /// Returns [`DidParseError::InvalidDid`] if the string is not a valid DID.
    pub fn parse(did: impl Into<String>) -> Result<Self, DidParseError> {
        let did = did.into();
        DID::new(&did).map_err(|e| DidParseError::InvalidDid {
            value: did.clone(),
            reason: e.1.to_string(),
        })?;
        Ok(Self(did))
    }

    /// Creates a new DID without validation.
    ///
    /// # Warning
    ///
    /// The caller must ensure the string is a valid DID.
    /// Prefer using [`Did::parse`] for untrusted input.
    /// This is mainly useful for tests or when the DID is known to be valid.
    pub fn new_unchecked(did: impl Into<String>) -> Self {
        Self(did.into())
    }

    /// Returns the DID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the method portion of the DID (e.g., "web" for "did:web:...").
    pub fn method(&self) -> &str {
        self.0
            .strip_prefix("did:")
            .and_then(|rest| rest.split(':').next())
            .unwrap_or("")
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Did::parse(s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A Key ID (DID URL) that references a verification method in a DID document.
///
/// Key IDs are DID URLs, typically with a fragment that identifies a specific
/// key within the DID document.
///
/// Format: `did:<method>:<method-specific-id>#<fragment>`
///
/// Examples:
/// - `did:web:api.agentium.network#key-1`
/// - `did:pkh:eip155:1:0x1234...#controller`
///
/// Validation is performed using the `ssi` crate's W3C-compliant DID URL parser.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    /// Parses and validates a KeyId (DID URL) string.
    ///
    /// Uses the `ssi` crate's W3C-compliant DID URL parser for validation.
    ///
    /// # Errors
    ///
    /// Returns [`DidParseError::InvalidDidUrl`] if the string is not a valid DID URL.
    pub fn parse(key_id: impl Into<String>) -> Result<Self, DidParseError> {
        let key_id = key_id.into();
        DIDURL::new(&key_id).map_err(|e| DidParseError::InvalidDidUrl {
            value: key_id.clone(),
            reason: e.1.to_string(),
        })?;
        Ok(Self(key_id))
    }

    /// Creates a new KeyId without validation.
    ///
    /// # Warning
    ///
    /// The caller must ensure the string is a valid DID URL.
    /// Prefer using [`KeyId::parse`] for untrusted input.
    /// This is mainly useful for tests or when the KeyId is known to be valid.
    pub fn new_unchecked(key_id: impl Into<String>) -> Self {
        Self(key_id.into())
    }

    /// Returns the KeyId as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extracts the fragment portion of the KeyId (the part after `#`).
    ///
    /// Returns `None` if there is no fragment.
    pub fn fragment(&self) -> Option<&str> {
        self.0.split_once('#').map(|(_, fragment)| fragment)
    }

    /// Checks if this KeyId matches a given key identifier.
    ///
    /// The `kid` can be:
    /// - A full KeyId (exact match)
    /// - Just the fragment (matches if this KeyId ends with `#fragment`)
    pub fn matches(&self, kid: &str) -> bool {
        self.0 == kid || self.0.ends_with(&format!("#{kid}"))
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        KeyId::parse(s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DID Document types
// ─────────────────────────────────────────────────────────────────────────────

/// JSON Web Key structure for Ed25519 keys.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct JsonWebKey {
    /// Key type (always "OKP" for Ed25519)
    pub kty: String,
    /// Curve (always "Ed25519")
    pub crv: String,
    /// Public key material (base64url encoded)
    pub x: String,
    /// Private key material (base64url encoded) - only present in private keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

/// Verification method within a DID Document.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VerificationMethod {
    /// Full key ID (e.g., "did:web:api.agentium.network#key-1")
    pub id: KeyId,
    /// Key type (e.g., "JsonWebKey2020")
    #[serde(rename = "type")]
    pub method_type: String,
    /// Controller DID
    pub controller: Did,
    /// Public key in JWK format
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: JsonWebKey,
}

/// W3C DID Document structure.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DidDocument {
    /// DID identifier (e.g., "did:web:api.agentium.network")
    pub id: Did,
    /// Verification methods containing public keys
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    /// Authentication method references
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<KeyId>>,
}

impl DidDocument {
    /// Extracts the public key JWK from this DID document.
    ///
    /// If a key ID (`kid`) is provided, finds the matching verification method.
    /// The `kid` can be:
    /// - A full key ID (e.g., `did:web:api.agentium.network#key-1`)
    /// - Just the fragment (e.g., `key-1`)
    ///
    /// If no `kid` is provided, returns the first verification method's public key.
    ///
    /// # Errors
    ///
    /// Returns [`VcError::InvalidJwk`] if:
    /// - The DID document has no verification methods
    /// - No verification method matches the provided `kid`
    pub fn extract_public_key_jwk(&self, kid: Option<&str>) -> Result<&JsonWebKey, VcError> {
        let methods = &self.verification_method;

        if methods.is_empty() {
            return Err(VcError::InvalidJwk(
                "No verification methods found in DID document".to_string(),
            ));
        }

        let verification_method = match kid {
            Some(kid) => methods.iter().find(|m| m.id.matches(kid)).ok_or_else(|| {
                VcError::InvalidJwk(format!("No public key found for kid: {kid}"))
            })?,
            None => &methods[0],
        };

        Ok(&verification_method.public_key_jwk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_did_document() -> DidDocument {
        DidDocument {
            id: Did::new_unchecked("did:web:api.agentium.network"),
            verification_method: vec![
                VerificationMethod {
                    id: KeyId::new_unchecked("did:web:api.agentium.network#key-1"),
                    method_type: "JsonWebKey2020".to_string(),
                    controller: Did::new_unchecked("did:web:api.agentium.network"),
                    public_key_jwk: JsonWebKey {
                        kty: "OKP".to_string(),
                        crv: "Ed25519".to_string(),
                        x: "test-key-1-x".to_string(),
                        d: None,
                    },
                },
                VerificationMethod {
                    id: KeyId::new_unchecked("did:web:api.agentium.network#key-2"),
                    method_type: "JsonWebKey2020".to_string(),
                    controller: Did::new_unchecked("did:web:api.agentium.network"),
                    public_key_jwk: JsonWebKey {
                        kty: "OKP".to_string(),
                        crv: "Ed25519".to_string(),
                        x: "test-key-2-x".to_string(),
                        d: None,
                    },
                },
            ],
            authentication: None,
        }
    }

    #[test]
    fn test_did_parse_valid() {
        let did = Did::parse("did:web:example.com").unwrap();
        assert_eq!(did.as_str(), "did:web:example.com");
        assert_eq!(did.method(), "web");
    }

    #[test]
    fn test_did_parse_invalid() {
        assert!(Did::parse("not-a-did").is_err());
        assert!(Did::parse("did:").is_err());
        assert!(Did::parse("").is_err());
    }

    #[test]
    fn test_did_display() {
        let did = Did::new_unchecked("did:web:example.com");
        assert_eq!(did.to_string(), "did:web:example.com");
        assert_eq!(did.as_str(), "did:web:example.com");
    }

    #[test]
    fn test_key_id_parse_valid() {
        let key_id = KeyId::parse("did:web:example.com#key-1").unwrap();
        assert_eq!(key_id.as_str(), "did:web:example.com#key-1");
        assert_eq!(key_id.fragment(), Some("key-1"));
    }

    #[test]
    fn test_key_id_parse_invalid() {
        assert!(KeyId::parse("not-a-did-url").is_err());
        assert!(KeyId::parse("").is_err());
    }

    #[test]
    fn test_key_id_fragment() {
        let key_id = KeyId::new_unchecked("did:web:example.com#key-1");
        assert_eq!(key_id.fragment(), Some("key-1"));

        let key_id_no_fragment = KeyId::new_unchecked("did:web:example.com");
        assert_eq!(key_id_no_fragment.fragment(), None);
    }

    #[test]
    fn test_key_id_matches() {
        let key_id = KeyId::new_unchecked("did:web:example.com#key-1");

        // Exact match
        assert!(key_id.matches("did:web:example.com#key-1"));
        // Fragment match
        assert!(key_id.matches("key-1"));
        // No match
        assert!(!key_id.matches("key-2"));
        assert!(!key_id.matches("did:web:other.com#key-1"));
    }

    #[test]
    fn test_extract_first_key_when_no_kid() {
        let doc = create_test_did_document();
        let key = doc.extract_public_key_jwk(None).unwrap();
        assert_eq!(key.x, "test-key-1-x");
    }

    #[test]
    fn test_extract_by_full_kid() {
        let doc = create_test_did_document();
        let key = doc
            .extract_public_key_jwk(Some("did:web:api.agentium.network#key-2"))
            .unwrap();
        assert_eq!(key.x, "test-key-2-x");
    }

    #[test]
    fn test_extract_by_fragment_kid() {
        let doc = create_test_did_document();
        let key = doc.extract_public_key_jwk(Some("key-2")).unwrap();
        assert_eq!(key.x, "test-key-2-x");
    }

    #[test]
    fn test_error_on_unknown_kid() {
        let doc = create_test_did_document();
        let result = doc.extract_public_key_jwk(Some("unknown-key"));
        assert!(result.is_err());
        assert!(matches!(result, Err(VcError::InvalidJwk(_))));
    }

    #[test]
    fn test_error_on_empty_verification_methods() {
        let doc = DidDocument {
            id: Did::new_unchecked("did:web:empty.example"),
            verification_method: vec![],
            authentication: None,
        };
        let result = doc.extract_public_key_jwk(None);
        assert!(result.is_err());
    }
}
