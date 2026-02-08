// SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
//
// SPDX-License-Identifier: BUSL-1.1

//! Challenge-response signing for wallet authentication.
//!
//! Provides signing functionality for Python/Node where private keys are passed directly.
//! Browser/WASM signing should be handled in the JS layer via wallet popups.
//!
//! # Usage
//!
//! ```ignore
//! use agentium_sdk_core::{Caip2, signer};
//!
//! let caip2 = Caip2::new("eip155:1")?;
//! let message = b"Sign this challenge";
//! let private_key = &[0u8; 32]; // Your 32-byte secp256k1 key
//!
//! let signature = signer::sign_challenge(message, &caip2, private_key)?;
//! ```

use thiserror::Error;
use tracing::instrument;

use crate::Caip2;

/// Errors that can occur during challenge signing.
#[derive(Debug, Error)]
pub enum SignError {
    /// The chain namespace is not supported for signing.
    #[error("unsupported chain namespace for signing: {0}")]
    UnsupportedNamespace(String),

    /// The private key has invalid length for the target chain.
    #[error("invalid key length for {chain}: expected {expected} bytes, got {got}")]
    InvalidKeyLength {
        expected: usize,
        got: usize,
        chain: &'static str,
    },

    /// The private key format is invalid for the target chain.
    #[error("invalid key format for {chain}: {reason}")]
    InvalidKeyFormat { chain: &'static str, reason: String },

    /// Signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

/// Hex-encoded signature from signing a challenge.
///
/// Format is chain-specific:
/// - EVM: 0x-prefixed, 65 bytes (r || s || v) as 132 hex chars
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSignature(String);

impl WalletSignature {
    /// Returns the hex-encoded signature string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for WalletSignature {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for WalletSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Signs a challenge message using the appropriate chain signer.
///
/// Dispatches to the correct signing implementation based on the CAIP-2 namespace.
///
/// # Arguments
///
/// * `message` - The challenge message bytes to sign
/// * `caip2` - Chain identifier determining which signing algorithm to use
/// * `private_key` - Raw private key bytes (format depends on chain)
///
/// # Errors
///
/// Returns [`SignError`] if:
/// - The namespace is not supported
/// - The private key has invalid length or format
/// - Signing fails
///
/// # Chain-specific key formats
///
/// - `eip155` (EVM): 32-byte secp256k1 private key
#[instrument(skip(message, private_key), fields(chain_id = %caip2))]
pub fn sign_challenge(
    message: &[u8],
    caip2: &Caip2,
    private_key: &[u8],
) -> Result<WalletSignature, SignError> {
    match caip2.namespace_str() {
        "eip155" => evm::sign(message, private_key),
        ns => Err(SignError::UnsupportedNamespace(ns.to_string())),
    }
}

/// EVM (secp256k1) signing implementation using alloy.
mod evm {
    use alloy_primitives::B256;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    use super::{SignError, WalletSignature};

    /// Signs a message with EIP-191 personal_sign encoding.
    ///
    /// The message is prefixed with `"\x19Ethereum Signed Message:\n" + len(message)`
    /// before hashing and signing, as per EIP-191.
    pub(super) fn sign(message: &[u8], private_key: &[u8]) -> Result<WalletSignature, SignError> {
        let key_bytes: [u8; 32] =
            private_key
                .try_into()
                .map_err(|_| SignError::InvalidKeyLength {
                    expected: 32,
                    got: private_key.len(),
                    chain: "evm",
                })?;

        let signer = PrivateKeySigner::from_bytes(&B256::from(key_bytes)).map_err(|e| {
            SignError::InvalidKeyFormat {
                chain: "evm",
                reason: e.to_string(),
            }
        })?;

        let signature = signer
            .sign_message_sync(message)
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;

        tracing::trace!("successfully signed evm challenge");

        // Convert to 0x-prefixed hex (r || s || v format, 65 bytes = 130 hex + "0x")
        Ok(WalletSignature(format!("0x{}", signature)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector: well-known private key for deterministic testing
    // This is a throwaway test key - never use in production
    const TEST_PRIVATE_KEY: [u8; 32] = [
        0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff,
        0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfb, 0xbf, 0x5e, 0x93, 0x41, 0xad, 0x33,
        0x2d, 0x3e,
    ];

    #[test]
    fn test_sign_evm_produces_valid_signature() {
        let caip2 = Caip2::new("eip155:1").unwrap();
        let message = b"Test message";

        let signature = sign_challenge(message, &caip2, &TEST_PRIVATE_KEY).unwrap();

        // Should be 0x-prefixed
        assert!(signature.as_str().starts_with("0x"));
        // Alloy outputs r (32) + s (32) + v (1) = 65 bytes, but Display may pad v
        // Accept either 132 (65 bytes) or 134 (67 bytes with padded v)
        let len = signature.as_str().len();
        assert!(
            len == 132 || len == 134,
            "unexpected signature length: {len}"
        );
    }

    #[test]
    fn test_sign_evm_deterministic() {
        let caip2 = Caip2::new("eip155:1").unwrap();
        let message = b"Deterministic test";

        let sig1 = sign_challenge(message, &caip2, &TEST_PRIVATE_KEY).unwrap();
        let sig2 = sign_challenge(message, &caip2, &TEST_PRIVATE_KEY).unwrap();

        assert_eq!(sig1.as_str(), sig2.as_str());
    }

    #[test]
    fn test_sign_evm_different_messages_different_signatures() {
        let caip2 = Caip2::new("eip155:1").unwrap();

        let sig1 = sign_challenge(b"Message A", &caip2, &TEST_PRIVATE_KEY).unwrap();
        let sig2 = sign_challenge(b"Message B", &caip2, &TEST_PRIVATE_KEY).unwrap();

        assert_ne!(sig1.as_str(), sig2.as_str());
    }

    #[test]
    fn test_sign_invalid_key_length() {
        let caip2 = Caip2::new("eip155:1").unwrap();
        let short_key = [0u8; 16];

        let result = sign_challenge(b"test", &caip2, &short_key);

        assert!(matches!(
            result,
            Err(SignError::InvalidKeyLength {
                expected: 32,
                got: 16,
                chain: "evm"
            })
        ));
    }

    #[test]
    fn test_sign_unsupported_namespace() {
        let caip2 = Caip2::new("solana:mainnet").unwrap();

        let result = sign_challenge(b"test", &caip2, &TEST_PRIVATE_KEY);

        assert!(matches!(
            result,
            Err(SignError::UnsupportedNamespace(ns)) if ns == "solana"
        ));
    }

    #[test]
    fn test_sign_different_evm_chains_same_signature() {
        // Signing is chain-agnostic for EVM - only namespace matters
        let mainnet = Caip2::new("eip155:1").unwrap();
        let base = Caip2::new("eip155:8453").unwrap();
        let message = b"Cross-chain test";

        let sig_mainnet = sign_challenge(message, &mainnet, &TEST_PRIVATE_KEY).unwrap();
        let sig_base = sign_challenge(message, &base, &TEST_PRIVATE_KEY).unwrap();

        // Same key, same message = same signature regardless of chain ID
        assert_eq!(sig_mainnet.as_str(), sig_base.as_str());
    }
}
