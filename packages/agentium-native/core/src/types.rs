// SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
//
// SPDX-License-Identifier: BUSL-1.1

use serde::{Deserialize, Serialize};

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
