// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

//! CAIP-2 chain identifier type.
//!
//! Provides a strongly-typed wrapper for CAIP-2 chain identifiers with validation.
//!
//! # TODO
//!
//! Consider extracting to a shared `agentium-types` crate to reuse with
//! payments-hub backend (see `lib/protocol-registry/src/crypto/caip2.rs`).
//! For now, duplicated here with minimal validation logic (no sqlx/alloy deps).

use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;

/// Errors that can occur when parsing or using CAIP-2 identifiers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Caip2Error {
    /// Missing colon separator between namespace and reference.
    #[error("CAIP-2 identifier must contain a colon separator")]
    MissingColon,

    /// Namespace validation failed.
    #[error("invalid namespace: {0}")]
    InvalidNamespace(NamespaceError),

    /// Reference validation failed.
    #[error("invalid reference: {0}")]
    InvalidReference(ReferenceError),

    /// Namespace is valid but not supported by this SDK.
    #[error("unsupported chain namespace: {0}")]
    UnsupportedNamespace(String),

    /// Reference is not a valid numeric chain ID (for EVM chains).
    #[error("chain reference is not a valid numeric ID: {0}")]
    InvalidChainId(String),
}

/// Namespace-specific validation errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NamespaceError {
    #[error("namespace must be at least 3 characters")]
    TooShort,
    #[error("namespace must be at most 8 characters")]
    TooLong,
    #[error("namespace must contain only lowercase alphanumeric characters and hyphens")]
    InvalidCharacters,
}

/// Reference-specific validation errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReferenceError {
    #[error("reference cannot be empty")]
    Empty,
    #[error("reference must be at most 32 characters")]
    TooLong,
    #[error("reference must contain only alphanumeric characters, hyphens, and underscores")]
    InvalidCharacters,
}

impl From<NamespaceError> for Caip2Error {
    fn from(e: NamespaceError) -> Self {
        Caip2Error::InvalidNamespace(e)
    }
}

impl From<ReferenceError> for Caip2Error {
    fn from(e: ReferenceError) -> Self {
        Caip2Error::InvalidReference(e)
    }
}

/// Chain namespace for dispatch in wallet authentication.
///
/// Used to route to chain-specific authentication logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainNamespace {
    /// EVM-compatible chains (Ethereum, Base, Polygon, etc.)
    /// Uses SIWE (EIP-4361) for authentication.
    Eip155,
    // Future namespaces:
    // Solana,
    // Cosmos,
    // Bip122, // Bitcoin
}

impl ChainNamespace {
    /// Returns the namespace string identifier.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainNamespace::Eip155 => "eip155",
        }
    }
}

impl fmt::Display for ChainNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// CAIP-2 chain identifier (e.g., "eip155:84532", "eip155:1").
///
/// Wraps a validated CAIP-2 string. The value is validated at construction time
/// and guaranteed to match the CAIP-2 format specification.
///
/// # Format
///
/// `namespace:reference`
/// - Namespace: 3-8 characters, lowercase alphanumeric + hyphens `[-a-z0-9]{3,8}`
/// - Reference: 1-32 characters, alphanumeric + hyphens + underscores `[-_a-zA-Z0-9]{1,32}`
///
/// # Reference
///
/// [CAIP-2 Specification](https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Caip2(String);

impl Caip2 {
    /// Creates a new CAIP-2 identifier with validation.
    ///
    /// # Errors
    ///
    /// Returns [`Caip2Error`] if the string doesn't match CAIP-2 format.
    pub fn new(caip2: &str) -> Result<Self, Caip2Error> {
        validate_caip2_format(caip2)?;
        Ok(Caip2(caip2.to_string()))
    }

    /// Returns the CAIP-2 string value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the namespace portion (e.g., "eip155" for "eip155:84532").
    ///
    /// This method is infallible for validated `Caip2` instances.
    #[must_use]
    pub fn namespace_str(&self) -> &str {
        // SAFETY: Caip2 is validated at construction to contain exactly one colon.
        // This split will always succeed for a valid instance.
        self.0
            .split_once(':')
            .map(|(ns, _)| ns)
            .unwrap_or_else(|| unreachable!("validated CAIP-2 must contain colon"))
    }

    /// Returns the reference portion (e.g., "84532" for "eip155:84532").
    ///
    /// This method is infallible for validated `Caip2` instances.
    #[must_use]
    pub fn reference(&self) -> &str {
        // SAFETY: Caip2 is validated at construction to contain exactly one colon.
        // This split will always succeed for a valid instance.
        self.0
            .split_once(':')
            .map(|(_, ref_)| ref_)
            .unwrap_or_else(|| unreachable!("validated CAIP-2 must contain colon"))
    }

    /// Parses the namespace into a [`ChainNamespace`] enum.
    ///
    /// Returns `None` if the namespace is valid but not yet supported by this SDK.
    /// The `Caip2` itself is still valid - this just means no enum variant exists.
    #[must_use]
    pub fn namespace(&self) -> Option<ChainNamespace> {
        match self.namespace_str() {
            "eip155" => Some(ChainNamespace::Eip155),
            _ => None,
        }
    }

    /// Extracts the numeric chain ID for EVM chains.
    ///
    /// Only valid for `eip155` namespace where the reference is a numeric chain ID.
    ///
    /// # Errors
    ///
    /// Returns [`Caip2Error::UnsupportedNamespace`] if not an EVM chain.
    /// Returns [`Caip2Error::InvalidChainId`] if the reference is not numeric.
    pub fn evm_chain_id(&self) -> Result<u64, Caip2Error> {
        let ns = self.namespace_str();
        if ns != "eip155" {
            return Err(Caip2Error::UnsupportedNamespace(ns.to_string()));
        }

        let reference = self.reference();
        reference
            .parse()
            .map_err(|_| Caip2Error::InvalidChainId(reference.to_string()))
    }
}

impl fmt::Display for Caip2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Caip2 {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Caip2 {
    type Error = Caip2Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Caip2::new(s)
    }
}

impl TryFrom<String> for Caip2 {
    type Error = Caip2Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Caip2::new(&s)
    }
}

impl<'de> Deserialize<'de> for Caip2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Caip2::try_from(s).map_err(serde::de::Error::custom)
    }
}

/// Validates CAIP-2 format per specification.
fn validate_caip2_format(caip2: &str) -> Result<(), Caip2Error> {
    let (namespace, reference) = caip2.split_once(':').ok_or(Caip2Error::MissingColon)?;

    // Validate namespace: [-a-z0-9]{3,8}
    if namespace.len() < 3 {
        return Err(NamespaceError::TooShort.into());
    }
    if namespace.len() > 8 {
        return Err(NamespaceError::TooLong.into());
    }
    if !namespace
        .bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(NamespaceError::InvalidCharacters.into());
    }

    // Validate reference: [-_a-zA-Z0-9]{1,32}
    if reference.is_empty() {
        return Err(ReferenceError::Empty.into());
    }
    if reference.len() > 32 {
        return Err(ReferenceError::TooLong.into());
    }
    if !reference
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(ReferenceError::InvalidCharacters.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_eip155() {
        let caip2 = Caip2::try_from("eip155:84532").unwrap();
        assert_eq!(caip2.as_str(), "eip155:84532");
        assert_eq!(caip2.namespace_str(), "eip155");
        assert_eq!(caip2.reference(), "84532");
        assert_eq!(caip2.namespace(), Some(ChainNamespace::Eip155));
        assert_eq!(caip2.evm_chain_id().unwrap(), 84532);
    }

    #[test]
    fn test_valid_ethereum_mainnet() {
        let caip2 = Caip2::try_from("eip155:1").unwrap();
        assert_eq!(caip2.evm_chain_id().unwrap(), 1);
    }

    #[test]
    fn test_valid_cosmos() {
        let caip2 = Caip2::try_from("cosmos:cosmoshub-4").unwrap();
        assert_eq!(caip2.namespace_str(), "cosmos");
        assert_eq!(caip2.reference(), "cosmoshub-4");
        // Cosmos not yet supported in ChainNamespace enum
        assert_eq!(caip2.namespace(), None);
        // evm_chain_id errors because cosmos is not eip155
        assert!(matches!(
            caip2.evm_chain_id(),
            Err(Caip2Error::UnsupportedNamespace(_))
        ));
    }

    #[test]
    fn test_valid_solana() {
        let caip2 = Caip2::try_from("solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ").unwrap();
        assert_eq!(caip2.namespace_str(), "solana");
        // Not yet supported in ChainNamespace enum
        assert_eq!(caip2.namespace(), None);
    }

    #[test]
    fn test_evm_chain_id_non_numeric_reference() {
        // EVM chain with non-numeric reference should error
        let caip2 = Caip2::try_from("eip155:mainnet").unwrap();
        assert!(matches!(
            caip2.evm_chain_id(),
            Err(Caip2Error::InvalidChainId(_))
        ));
    }

    #[test]
    fn test_valid_min_namespace() {
        // Minimum 3 char namespace
        let caip2 = Caip2::try_from("btc:mainnet").unwrap();
        assert_eq!(caip2.namespace_str(), "btc");
    }

    #[test]
    fn test_valid_max_namespace() {
        // Maximum 8 char namespace
        let caip2 = Caip2::try_from("polkadot:mainnet").unwrap();
        assert_eq!(caip2.namespace_str(), "polkadot");
    }

    #[test]
    fn test_valid_underscore_in_reference() {
        let caip2 = Caip2::try_from("near:test_network").unwrap();
        assert_eq!(caip2.reference(), "test_network");
    }

    #[test]
    fn test_invalid_missing_colon() {
        let result = Caip2::try_from("eip155");
        assert!(matches!(result, Err(Caip2Error::MissingColon)));
    }

    #[test]
    fn test_invalid_empty_namespace() {
        let result = Caip2::try_from(":84532");
        assert!(matches!(
            result,
            Err(Caip2Error::InvalidNamespace(NamespaceError::TooShort))
        ));
    }

    #[test]
    fn test_invalid_empty_reference() {
        let result = Caip2::try_from("eip155:");
        assert!(matches!(
            result,
            Err(Caip2Error::InvalidReference(ReferenceError::Empty))
        ));
    }

    #[test]
    fn test_invalid_namespace_too_short() {
        let result = Caip2::try_from("ab:123");
        assert!(matches!(
            result,
            Err(Caip2Error::InvalidNamespace(NamespaceError::TooShort))
        ));
    }

    #[test]
    fn test_invalid_namespace_too_long() {
        let result = Caip2::try_from("toolongns:123");
        assert!(matches!(
            result,
            Err(Caip2Error::InvalidNamespace(NamespaceError::TooLong))
        ));
    }

    #[test]
    fn test_invalid_uppercase_namespace() {
        let result = Caip2::try_from("EIP155:1");
        assert!(matches!(
            result,
            Err(Caip2Error::InvalidNamespace(
                NamespaceError::InvalidCharacters
            ))
        ));
    }

    #[test]
    fn test_invalid_reference_too_long() {
        let result = Caip2::try_from("eip155:123456789012345678901234567890123");
        assert!(matches!(
            result,
            Err(Caip2Error::InvalidReference(ReferenceError::TooLong))
        ));
    }

    #[test]
    fn test_invalid_special_chars_in_reference() {
        let result = Caip2::try_from("eip155:test@chain");
        assert!(matches!(
            result,
            Err(Caip2Error::InvalidReference(
                ReferenceError::InvalidCharacters
            ))
        ));
    }

    #[test]
    fn test_display() {
        let caip2 = Caip2::try_from("eip155:84532").unwrap();
        assert_eq!(format!("{}", caip2), "eip155:84532");
    }

    #[test]
    fn test_try_from_string() {
        let caip2 = Caip2::try_from("eip155:84532".to_string()).unwrap();
        assert_eq!(caip2.as_str(), "eip155:84532");
    }

    #[test]
    fn test_serde_roundtrip() {
        let caip2 = Caip2::try_from("eip155:84532").unwrap();
        let json = serde_json::to_string(&caip2).unwrap();
        assert_eq!(json, "\"eip155:84532\"");

        let parsed: Caip2 = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, caip2);
    }

    #[test]
    fn test_chain_namespace_display() {
        assert_eq!(ChainNamespace::Eip155.as_str(), "eip155");
        assert_eq!(format!("{}", ChainNamespace::Eip155), "eip155");
    }
}
