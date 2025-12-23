// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

use agentium_sdk_core::{JwtError, VcError};
use serde::Serialize;
use wasm_bindgen::JsValue;

#[derive(Serialize)]
pub struct JsErrorObj<'a> {
    pub code: &'a str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl From<VcError> for JsErrorObj<'static> {
    fn from(err: VcError) -> Self {
        let (code, message, data) = match err {
            VcError::JwtExpired(exp) => (
                "JWT_EXPIRED",
                format!("JWT expired at {exp}"),
                Some(serde_json::json!({ "expiredAt": exp })),
            ),
            VcError::InvalidJwt(s) => (
                "INVALID_JWT_FORMAT",
                format!("Invalid JWT format: {s}"),
                None,
            ),
            VcError::InvalidJwk(s) => ("INVALID_JWK", s, None),
            VcError::VerificationFailed(e) => ("VERIFICATION_FAILED", e.to_string(), None),
            VcError::ClaimsValidation(s) => ("CLAIMS_VALIDATION", s, None),
            VcError::Serialization(e) => ("SERIALIZATION_ERROR", e.to_string(), None),
            VcError::DecodeError(e) => ("DECODE_ERROR", e.to_string(), None),
            VcError::KeyGeneration(e) => ("KEY_GENERATION", e.to_string(), None),
            VcError::SigningFailed(e) => ("SIGNING_FAILED", e.to_string(), None),
        };
        JsErrorObj {
            code,
            message,
            data,
        }
    }
}

impl<'a> From<JsErrorObj<'a>> for JsValue {
    fn from(obj: JsErrorObj) -> Self {
        match serde_wasm_bindgen::to_value(&obj) {
            Ok(v) => v,
            Err(_) => JsValue::from_str(&obj.message),
        }
    }
}

impl<'a> From<serde_json::Error> for JsErrorObj<'a> {
    fn from(value: serde_json::Error) -> Self {
        Self {
            code: "SERIALIZATION_ERROR",
            message: value.to_string(),
            data: None,
        }
    }
}

impl<'a> From<JwtError> for JsErrorObj<'a> {
    fn from(value: JwtError) -> Self {
        let (code, message) = match &value {
            JwtError::Parts => (
                "INVALID_JWT_FORMAT",
                "JWT must have exactly 3 dot-separated parts".to_string(),
            ),
            JwtError::Base64(e) => ("DECODE_ERROR", format!("Invalid Base64url: {e}")),
            JwtError::InvalidClaims(e) => (
                "INVALID_JWT_FORMAT",
                format!("Could not deserialize claims: {e}"),
            ),
        };
        Self {
            code,
            message,
            data: None,
        }
    }
}
