// SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
//
// SPDX-License-Identifier: BUSL-1.1

//! JWT Verifiable Credential (JWT-VC) verification.
//!
//! This module provides functionality for verifying JWT-encoded W3C Verifiable
//! Credentials using Ed25519 signatures. It implements the verification side
//! of the JWT-VC specification, validating both cryptographic signatures and
//! temporal claims (expiration).
//!
//! ## Responsibilities
//!
//! This module handles:
//! - Cryptographic signature verification using Ed25519
//! - JWT structure validation
//! - Expiration time validation
//! - Claims extraction and deserialization
//!
//! ## Caller Responsibilities
//!
//! The caller is responsible for:
//! - Securely obtaining the correct public key for verification
//! - Resolving DIDs to obtain public keys (e.g., via did:web resolution)
//! - Handling verification failures appropriately

pub use crate::VcError;
use crate::key_pair::PublicKey;
use crate::{JwtRef, types::*};

/// Verifies a JWT-VC against a provided public key.
///
/// This function performs complete JWT verification including:
/// - Structural validation of the JWT format
/// - Cryptographic signature verification using the provided public key
/// - Expiration time validation against the current system time
///
/// On success, returns the deserialized [`JwtClaims`] containing the
/// Verifiable Credential and associated metadata.
///
/// # Errors
///
/// Returns [`VcError`] if:
/// - The JWT structure is invalid
/// - The signature verification fails
/// - The JWT has expired
/// - The claims cannot be deserialized
pub fn verify_jwt(jwt: &str, public_key: &PublicKey) -> Result<JwtClaims, VcError> {
    let key = public_key.jwk_key();

    let jwt = JwtRef::try_from(jwt)?;

    let signature_bytes = jwt.signature_bytes();

    let algorithm = key.get_algorithm().unwrap_or(ssi::jwk::Algorithm::EdDSA);

    ssi::claims::jws::verify_bytes(
        algorithm,
        jwt.signing_input().as_bytes(),
        key,
        &signature_bytes,
    )?;

    let claims: JwtClaims = jwt.claims()?;

    let now = chrono::Utc::now().timestamp();
    if claims.exp < now {
        let expired_at = chrono::DateTime::from_timestamp(claims.exp, 0)
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| claims.exp.to_string());
        tracing::error!(expired_at, "JWT expired");
        return Err(VcError::JwtExpired(expired_at));
    }

    tracing::debug!(
        issuer = %claims.vc.issuer.id,
        subject = %claims.sub,
        "JWT verification successful"
    );

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;
    use ssi::jwk::JWK;

    /// Issue a W3C-compliant JWT-VC for testing
    fn issue_jwt(
        issuer_did: &str,
        subject_did: &str,
        enrollment_time: &str,
        private_key_jwk: &JWK,
        expires_in_hours: Option<i32>,
    ) -> Result<String, VcError> {
        use base64::Engine;

        let key = private_key_jwk;

        let now = chrono::Utc::now();
        let hours = expires_in_hours.unwrap_or(24) as i64;
        let exp = now.timestamp() + (hours * 3600);

        // Build W3C VC structure matching backend SSI output
        let claims = JwtClaims {
            vc: VerifiableCredential {
                context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
                credential_type: vec!["VerifiableCredential".to_string()],
                issuer: Issuer {
                    id: issuer_did.to_string(),
                },
                issuance_date: enrollment_time.to_string(),
                credential_subject: CredentialSubject {
                    id: subject_did.to_string(),
                    enrollment_time: enrollment_time.to_string(),
                },
            },
            sub: subject_did.to_string(),
            exp,
            iat: now.timestamp(),
        };

        let claims_json = serde_json::to_string(&claims)?;

        let algorithm = key.get_algorithm().unwrap_or(ssi::jwk::Algorithm::EdDSA);

        // Build JWT header
        let header = serde_json::json!({
            "alg": algorithm.to_string(),
            "typ": "JWT"
        });
        let header_json = serde_json::to_string(&header)?;

        // Base64url encode header and payload
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

        // Create signing input
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign
        let signature = ssi::claims::jws::sign_bytes(algorithm, signing_input.as_bytes(), key)
            .map_err(VcError::SigningFailed)?;

        // Base64url encode signature
        let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

        // Return compact JWT
        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }

    fn generate_did_document(
        did: &str,
        public_key_jwk: &JWK,
        key_id: Option<String>,
    ) -> Result<String, VcError> {
        let public_key: serde_json::Value =
            serde_json::to_value(public_key_jwk).map_err(|e| VcError::InvalidJwk(e.to_string()))?;

        let key_fragment = key_id.unwrap_or_else(|| "key-1".to_string());
        let full_key_id = format!("{}#{}", did, key_fragment);

        let did_document = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ],
            "id": did,
            "verificationMethod": [{
                "id": full_key_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_key
            }],
            "assertionMethod": [full_key_id],
            "authentication": [full_key_id]
        });

        serde_json::to_string_pretty(&did_document).map_err(VcError::Serialization)
    }
    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::new().unwrap();
        let public_jwk = keypair.public_jwk();
        let public_jwk_str = serde_json::to_string(&public_jwk).unwrap();

        assert!(public_jwk_str.contains("\"kty\":\"OKP\""));
        // Public key should NOT have 'd' parameter
        assert!(!public_jwk_str.contains("\"d\":"));
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::new().unwrap();
        let enrollment_time = "2024-01-15T10:30:00Z";

        // Get internal JWK for issuing (in tests we need access to private key)
        let keypair_str = serde_json::to_string(&keypair).unwrap();
        let keypair_value: serde_json::Value = serde_json::from_str(&keypair_str).unwrap();
        let private_jwk: JWK =
            serde_json::from_value(keypair_value["private_key"].clone()).unwrap();

        // Issue JWT with W3C VC structure
        let jwt = issue_jwt(
            "did:web:test.example",
            "did:pkh:eip155:1:0x1234567890abcdef",
            enrollment_time,
            &private_jwk,
            Some(24),
        )
        .unwrap();

        assert!(jwt.contains('.'));
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Convert public JWK to PublicKey for verification
        let public_key_str = serde_json::to_string(&keypair.public_jwk()).unwrap();
        let public_key = PublicKey::try_from(public_key_str.as_str()).unwrap();

        // Verify JWT
        let claims = verify_jwt(&jwt, &public_key).unwrap();

        assert_eq!(claims.vc.issuer.id, "did:web:test.example");
        assert_eq!(claims.sub, "did:pkh:eip155:1:0x1234567890abcdef");
        assert_eq!(
            claims.vc.credential_subject.id,
            "did:pkh:eip155:1:0x1234567890abcdef"
        );
        assert_eq!(
            claims.vc.credential_subject.enrollment_time,
            enrollment_time
        );
    }

    #[test]
    fn test_verification_fails_with_wrong_key() {
        let issuer_keypair = KeyPair::new().unwrap();
        let wrong_keypair = KeyPair::new().unwrap();

        // Get private JWK for issuing
        let keypair_str = serde_json::to_string(&issuer_keypair).unwrap();
        let keypair_value: serde_json::Value = serde_json::from_str(&keypair_str).unwrap();
        let private_jwk: JWK =
            serde_json::from_value(keypair_value["private_key"].clone()).unwrap();

        let jwt = issue_jwt(
            "did:web:test.example",
            "did:pkh:eip155:1:0x1234567890abcdef",
            "2024-01-15T10:30:00Z",
            &private_jwk,
            Some(24),
        )
        .unwrap();

        // Use wrong keypair's public key for verification
        let wrong_public_key_str = serde_json::to_string(&wrong_keypair.public_jwk()).unwrap();
        let wrong_public_key = PublicKey::try_from(wrong_public_key_str.as_str()).unwrap();

        let result = verify_jwt(&jwt, &wrong_public_key);

        assert!(result.is_err());
    }

    #[test]
    fn test_did_document_generation() {
        let keypair = KeyPair::new().unwrap();

        let did_doc =
            generate_did_document("did:web:agentium.xyz", &keypair.public_jwk(), None).unwrap();

        let doc: serde_json::Value = serde_json::from_str(&did_doc).unwrap();
        assert_eq!(doc["id"], "did:web:agentium.xyz");
        assert!(
            doc["verificationMethod"][0]["publicKeyJwk"]["kty"]
                .as_str()
                .unwrap()
                .contains("OKP")
        );
    }

    #[test]
    fn test_get_public_key() {
        let keypair = KeyPair::new().unwrap();

        // Get private key and extract public from it
        let keypair_str = serde_json::to_string(&keypair).unwrap();
        let keypair_value: serde_json::Value = serde_json::from_str(&keypair_str).unwrap();
        let private_jwk: JWK =
            serde_json::from_value(keypair_value["private_key"].clone()).unwrap();
        let extracted_public = private_jwk.to_public();

        // Both should represent the same public key
        let original = keypair.public_jwk();
        let original_value = serde_json::to_value(&original).unwrap();
        let extracted_value = serde_json::to_value(&extracted_public).unwrap();

        assert_eq!(original_value["kty"], extracted_value["kty"]);
        assert_eq!(original_value["crv"], extracted_value["crv"]);
        assert_eq!(original_value["x"], extracted_value["x"]);
    }
}
