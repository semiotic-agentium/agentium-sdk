// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

//! WASM library for JWT-VC issuance and verification
//!
//! This library provides simple functions for:
//! - Generating Ed25519 key pairs (JWK format)
//! - Issuing JWT-VCs with membership claims
//! - Verifying JWTs against a provided public key
//!
//! The caller is responsible for:
//! - Storing/managing private keys securely
//! - Fetching public keys (e.g., from did:web resolution)
//! - Passing the correct public key for verification

use ssi::jwk::JWK;
use wasm_bindgen::prelude::*;

pub use crate::VcError;
use crate::types::*;

/// Generate a new Ed25519 key pair
///
/// Returns a JSON object with `private_jwk` and `public_jwk` fields.
/// The private key should be stored securely and never exposed.
#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    let key_pair = generate_keypair_impl()?;
    key_pair.try_into()
}

/// Verify a JWT against a public key
///
/// # Arguments
/// * `jwt` - The JWT string to verify (compact format: header.payload.signature)
/// * `public_key_jwk` - The public key as JWK JSON string
/// * `check_expiration` - Whether to check if the JWT has expired (default: true)
///
/// # Returns
/// A VerificationResult with validity status and decoded claims if valid
#[wasm_bindgen]
pub fn verify_jwt(
    jwt: &str,
    public_key_jwk: &str,
    check_expiration: Option<bool>,
) -> Result<JsValue, JsValue> {
    verify_jwt_impl(jwt, public_key_jwk, check_expiration.unwrap_or(true))
        .map_err(JsValue::from)
        .and_then(|res| res.try_into())
}

/// Extract public key from a private JWK
///
/// # Arguments
/// * `private_key_jwk` - The private key as JWK JSON string
///
/// # Returns
/// The public key as JWK JSON string
#[wasm_bindgen]
pub fn get_public_key(private_key_jwk: &str) -> Result<String, JsValue> {
    get_public_key_impl(private_key_jwk).map_err(|e| e.into())
}

fn generate_keypair_impl() -> Result<KeyPair, VcError> {
    let jwk = JWK::generate_ed25519()?;
    let public_jwk = jwk.to_public();

    Ok(KeyPair {
        private_jwk: serde_json::to_string(&jwk)?,
        public_jwk: serde_json::to_string(&public_jwk)?,
    })
}

fn verify_jwt_impl(
    jwt: &str,
    public_key_jwk: &str,
    check_expiration: bool,
) -> Result<VerificationResult, VcError> {
    let key: JWK = serde_json::from_str(public_key_jwk)?;

    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(VcError::InvalidJwk(
            "Invalid JWT format: missing sections".to_string(),
        ));
    }

    use base64::Engine;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let algorithm = key.get_algorithm().unwrap_or(ssi::jwk::Algorithm::EdDSA);

    if let Err(e) =
        ssi::claims::jws::verify_bytes(algorithm, signing_input.as_bytes(), &key, &signature)
    {
        tracing::error!(error = %e, "Signature verification failed");
        return Err(VcError::VerificationFailed(format!(
            "Signature verification failed: {e}"
        )));
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;

    let claims: JwtClaims = serde_json::from_slice(&payload_bytes)?;

    if check_expiration {
        let now = chrono::Utc::now().timestamp();
        if claims.exp < now {
            let expired_at = chrono::DateTime::from_timestamp(claims.exp, 0)
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| claims.exp.to_string());
            tracing::error!(expired_at, "JWT expired");
            return Err(VcError::JwtExpired(expired_at));
        }
    }

    tracing::debug!(
        issuer = %claims.vc.issuer.id,
        subject = %claims.sub,
        "JWT verification successful"
    );

    Ok(VerificationResult {
        valid: true,
        claims: Some(claims),
        error: None,
    })
}

fn get_public_key_impl(private_key_jwk: &str) -> Result<String, VcError> {
    let jwk: JWK = serde_json::from_str(private_key_jwk)?;
    let public_jwk = jwk.to_public();
    serde_json::to_string(&public_jwk).map_err(VcError::Serialization)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue a W3C-compliant JWT-VC for testing
    fn issue_jwt(
        issuer_did: &str,
        subject_did: &str,
        enrollment_time: &str,
        private_key_jwk: &str,
        expires_in_hours: Option<i32>,
    ) -> Result<String, VcError> {
        use base64::Engine;

        let key: JWK = serde_json::from_str(private_key_jwk)?;

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
        let signature = ssi::claims::jws::sign_bytes(algorithm, signing_input.as_bytes(), &key)
            .map_err(VcError::SigningFailed)?;

        // Base64url encode signature
        let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

        // Return compact JWT
        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }

    fn generate_did_document(
        did: &str,
        public_key_jwk: &str,
        key_id: Option<String>,
    ) -> Result<String, VcError> {
        let public_key: serde_json::Value =
            serde_json::from_str(public_key_jwk).map_err(|e| VcError::InvalidJwk(e.to_string()))?;

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
        let keypair = generate_keypair_impl().unwrap();

        assert!(keypair.private_jwk.contains("\"kty\":\"OKP\""));
        assert!(keypair.public_jwk.contains("\"kty\":\"OKP\""));
        // Private key should have 'd' parameter
        assert!(keypair.private_jwk.contains("\"d\":"));
        // Public key should NOT have 'd' parameter
        assert!(!keypair.public_jwk.contains("\"d\":"));
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = generate_keypair_impl().unwrap();
        let enrollment_time = "2024-01-15T10:30:00Z";

        // Issue JWT with W3C VC structure
        let jwt = issue_jwt(
            "did:web:test.example",
            "did:pkh:eip155:1:0x1234567890abcdef",
            enrollment_time,
            &keypair.private_jwk,
            Some(24),
        )
        .unwrap();

        assert!(jwt.contains('.'));
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Verify JWT (skip expiration check for test)
        let result = verify_jwt_impl(&jwt, &keypair.public_jwk, false).unwrap();

        assert!(result.valid);
        assert!(result.error.is_none());

        let claims = result.claims.unwrap();
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
        let issuer_keypair = generate_keypair_impl().unwrap();
        let wrong_keypair = generate_keypair_impl().unwrap();

        let jwt = issue_jwt(
            "did:web:test.example",
            "did:pkh:eip155:1:0x1234567890abcdef",
            "2024-01-15T10:30:00Z",
            &issuer_keypair.private_jwk,
            Some(24),
        )
        .unwrap();

        let result = verify_jwt_impl(&jwt, &wrong_keypair.public_jwk, false);

        assert!(result.is_err());
    }

    #[test]
    fn test_did_document_generation() {
        let keypair = generate_keypair_impl().unwrap();

        let did_doc =
            generate_did_document("did:web:agentium.xyz", &keypair.public_jwk, None).unwrap();

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
        let keypair = generate_keypair_impl().unwrap();
        let extracted_public = get_public_key_impl(&keypair.private_jwk).unwrap();

        // Both should represent the same public key
        let original: serde_json::Value = serde_json::from_str(&keypair.public_jwk).unwrap();
        let extracted: serde_json::Value = serde_json::from_str(&extracted_public).unwrap();

        assert_eq!(original["kty"], extracted["kty"]);
        assert_eq!(original["crv"], extracted["crv"]);
        assert_eq!(original["x"], extracted["x"]);
    }
}
