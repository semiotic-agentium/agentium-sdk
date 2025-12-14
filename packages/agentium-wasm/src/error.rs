// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

use base64::DecodeError;
use serde::Serialize;
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

    #[error("Jwt expired at {0}")]
    JwtExpired(String),
}

#[derive(Serialize)]
pub struct JsErrorObj<'a> {
    pub code: &'a str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl From<VcError> for JsValue {
    fn from(err: VcError) -> Self {
        use VcError::*;
        let (code, message, data) = match err {
            JwtExpired(exp) => (
                "JWT_EXPIRED",
                format!("JWT expired at {exp}"),
                Some(serde_json::json!({ "expiredAt": exp })),
            ),
            InvalidJwtFormat(s) => (
                "INVALID_JWT_FORMAT",
                format!("Invalid JWT format: {s}"),
                None,
            ),
            InvalidJwk(s) => ("INVALID_JWK", s, None),
            VerificationFailed(s) => ("VERIFICATION_FAILED", s, None),
            ClaimsValidation(s) => ("CLAIMS_VALIDATION", s, None),
            Serialization(e) => ("SERIALIZATION_ERROR", e.to_string(), None),
            DecodeError(e) => ("DECODE_ERROR", e.to_string(), None),
            KeyGeneration(e) => ("KEY_GENERATION", e.to_string(), None),
            SigningFailed(e) => ("SIGNING_FAILED", e.to_string(), None),
        };

        let obj = JsErrorObj {
            code,
            message,
            data,
        };

        match serde_wasm_bindgen::to_value(&obj) {
            Ok(v) => v,
            Err(_) => JsValue::from_str(&obj.message),
        }
    }
}
