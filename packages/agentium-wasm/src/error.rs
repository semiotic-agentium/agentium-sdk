// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

use base64::DecodeError;
use thiserror::Error;
use wasm_bindgen::JsValue;

#[derive(Error, Debug)]
pub enum VcError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(#[from] ssi::jwk::Error),

    #[error("Invalid JWK: {0}")]
    InvalidJwk(String),

    #[error("Signing failed: {0}")]
    SigningFailed(ssi::claims::jws::Error),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid JWT format: {0}")]
    InvalidJwtFormat(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Claims validation failed: {0}")]
    ClaimsValidation(String),

    #[error("Decode error: {0}")]
    DecodeError(#[from] DecodeError),
}

impl From<VcError> for JsValue {
    fn from(err: VcError) -> Self {
        JsValue::from_str(&err.to_string())
    }
}
