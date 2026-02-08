// SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
//
// SPDX-License-Identifier: BUSL-1.1

use agentium_sdk_core::{JwtClaims, VcError};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;

use crate::error::JsErrorObj;

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

impl From<VcError> for VerificationError {
    fn from(err: VcError) -> Self {
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
