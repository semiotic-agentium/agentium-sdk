// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use zeroize::Zeroize;
/// Key pair containing both private and public JWK
#[derive(Serialize, Deserialize, Zeroize)]
pub struct KeyPair {
    /// Full JWK with private key material (keep secret!)
    pub private_jwk: String,
    /// Public JWK (safe to share)
    pub public_jwk: String,
}

impl TryFrom<KeyPair> for JsValue {
    type Error = JsValue;

    fn try_from(value: KeyPair) -> Result<Self, Self::Error> {
        let res = serde_wasm_bindgen::to_value(&value)?;
        Ok(res)
    }
}

/// Membership credential claims
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MembershipClaims {
    /// Privy user ID or wallet address
    pub member_id: String,
    /// Membership status (e.g., "active")
    pub status: String,
}

/// JWT claims structure for membership VCs
#[derive(Serialize, Deserialize)]
pub struct JwtClaims {
    /// Issuer (e.g., "did:web:agentium.xyz")
    pub(crate) iss: String,
    /// Subject (user identifier)
    pub(crate) sub: String,
    /// Expiration time (Unix timestamp)
    pub(crate) exp: i64,
    /// Issued at (Unix timestamp)
    pub(crate) iat: i64,
    /// Custom membership claims
    pub(crate) membership: MembershipClaims,
}

/// Result of JWT verification
#[derive(Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the signature is valid
    pub valid: bool,
    /// Decoded claims if valid
    pub claims: Option<DecodedClaims>,
    /// Error message if invalid
    pub error: Option<String>,
}

impl VerificationResult {
    /// Create an error result with a contextual message
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            valid: false,
            claims: None,
            error: Some(msg.into()),
        }
    }
}

impl TryFrom<VerificationResult> for JsValue {
    type Error = JsValue;

    fn try_from(value: VerificationResult) -> Result<Self, Self::Error> {
        Ok(serde_wasm_bindgen::to_value(&value)?)
    }
}

/// Decoded JWT claims
#[derive(Serialize, Deserialize)]
pub struct DecodedClaims {
    pub issuer: String,
    pub subject: String,
    pub expires_at: i64,
    pub issued_at: i64,
    pub membership: MembershipClaims,
}
