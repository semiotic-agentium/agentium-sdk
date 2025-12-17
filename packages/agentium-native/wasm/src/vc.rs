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

use agentium_sdk_core::{KeyPair, PrivateKey, PublicKey, verify_jwt as sdk_core_verify};
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
