// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use zeroize::Zeroize;

use crate::error::JsErrorObj;

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

/// Structured error info for verification failures
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VerificationError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl<'a> From<JsErrorObj<'a>> for VerificationError {
    fn from(obj: JsErrorObj<'a>) -> Self {
        Self {
            code: obj.code.to_string(),
            message: obj.message,
            data: obj.data,
        }
    }
}

impl From<crate::VcError> for VerificationError {
    fn from(err: crate::VcError) -> Self {
        let obj: JsErrorObj<'static> = err.into();
        obj.into()
    }
}

/// Result of JWT verification
#[derive(Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the signature is valid
    pub valid: bool,
    /// JWT claims if valid (matches backend structure exactly)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<JwtClaims>,
    /// Structured error if invalid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<VerificationError>,
}

impl VerificationResult {
    /// Create an error result from a structured error
    pub fn from_error(err: VerificationError) -> Self {
        Self {
            valid: false,
            claims: None,
            error: Some(err),
        }
    }
}

impl TryFrom<VerificationResult> for JsValue {
    type Error = JsValue;

    fn try_from(value: VerificationResult) -> Result<Self, Self::Error> {
        Ok(serde_wasm_bindgen::to_value(&value)?)
    }
}
