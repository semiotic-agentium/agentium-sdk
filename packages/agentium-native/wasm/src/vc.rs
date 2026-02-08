// SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
//
// SPDX-License-Identifier: BUSL-1.1

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

use agentium_sdk_core::{
    DidDocument, JwtRef, KeyPair, PrivateKey, PublicKey, verify_jwt as sdk_core_verify,
};
use wasm_bindgen::prelude::*;

use crate::error::JsErrorObj;
use crate::types::*;

/// Generate a new Ed25519 key pair
///
/// Returns a JSON object with `private_jwk` and `public_jwk` fields.
/// The private key should be stored securely and never exposed.
#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    let key_pair = KeyPair::new().map_err(JsErrorObj::from)?;
    Ok(serde_wasm_bindgen::to_value(&key_pair)?)
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
pub fn verify_jwt(jwt: &str, public_key_jwk: &str) -> Result<JsValue, JsValue> {
    let pubkey: PublicKey = public_key_jwk.try_into().map_err(JsErrorObj::from)?;

    let result = match sdk_core_verify(jwt, &pubkey) {
        Ok(res) => VerificationResult {
            valid: true,
            claims: Some(res),
            error: None,
        },
        Err(err) => VerificationResult::from_error(err.into()),
    };
    result.try_into()
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
    let pubkey = PrivateKey::try_from(private_key_jwk)
        .map_err(JsErrorObj::from)?
        .pubkey();
    Ok(serde_json::to_string(pubkey.jwk_key()).map_err(JsErrorObj::from)?)
}

/// Parse a JWT header without verifying the signature.
///
/// # Arguments
/// * `jwt` - The JWT string (compact format: header.payload.signature)
///
/// # Returns
/// The parsed JWT header containing algorithm, type, and optional key ID.
#[wasm_bindgen]
pub fn parse_jwt_header(jwt: &str) -> Result<JsValue, JsValue> {
    let jwt_ref = JwtRef::try_from(jwt).map_err(JsErrorObj::from)?;
    let header = jwt_ref.header_claims().map_err(JsErrorObj::from)?;
    Ok(serde_wasm_bindgen::to_value(&header)?)
}

/// Extract the public key JWK from a DID document.
///
/// # Arguments
/// * `did_document_json` - The DID document as JSON string
/// * `kid` - Optional key ID to match (from JWT header). Can be full ID or just fragment.
///
/// # Returns
/// The public key as JWK JSON string
#[wasm_bindgen]
pub fn extract_public_key_jwk(
    did_document_json: &str,
    kid: Option<String>,
) -> Result<String, JsValue> {
    let did_document: DidDocument =
        serde_json::from_str(did_document_json).map_err(JsErrorObj::from)?;

    let jwk = did_document
        .extract_public_key_jwk(kid.as_deref())
        .map_err(JsErrorObj::from)?;

    serde_json::to_string(jwk).map_err(|e| JsErrorObj::from(e).into())
}
