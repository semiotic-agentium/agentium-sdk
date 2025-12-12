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

// ─────────────────────────────────────────────────────────────────────────────
// W3C Verifiable Credential Types (aligned with backend SSI implementation)
// ─────────────────────────────────────────────────────────────────────────────

/// Credential subject containing user identity and enrollment info.
/// Matches backend's MembershipCredentialSubject.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CredentialSubject {
    /// User's DID (did:pkh)
    pub id: String,
    /// Enrollment timestamp (ISO 8601 format)
    #[serde(rename = "enrollmentTime")]
    pub enrollment_time: String,
}

/// Issuer structure (can be string or object with id)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Issuer {
    /// Issuer DID
    pub id: String,
}

/// W3C Verifiable Credential structure.
/// Backend issues VCs using SSI library with this structure.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VerifiableCredential {
    /// JSON-LD context
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// Credential types
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    /// Issuer DID (as object with id)
    pub issuer: Issuer,
    /// Issuance date (ISO 8601 format)
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    /// Credential subject with user info
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
}

/// JWT claims structure for W3C VC (as issued by backend).
/// The VC is nested under the 'vc' claim per JWT-VC spec.
/// Returned directly from verification - matches backend exactly.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JwtClaims {
    /// The Verifiable Credential
    pub vc: VerifiableCredential,
    /// Subject (user DID)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp, optional)
    #[serde(default)]
    pub iat: i64,
}

/// Result of JWT verification
#[derive(Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the signature is valid
    pub valid: bool,
    /// JWT claims if valid (matches backend structure exactly)
    pub claims: Option<JwtClaims>,
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
