// SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
//
// SPDX-License-Identifier: BUSL-1.1

use base64::DecodeError;
use thiserror::Error;

use crate::JwtError;

#[derive(Error, Debug)]
pub enum VcError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(#[from] ssi::jwk::Error),

    #[error("Invalid JWK: {0}")]
    InvalidJwk(String),

    #[error("Signing failed: {0}")]
    SigningFailed(ssi::claims::jws::Error),

    #[error("Signature verification failed: {0}")]
    VerificationFailed(#[from] ssi::claims::jws::Error),

    #[error("Invalid JWT format: {0}")]
    InvalidJwt(#[from] JwtError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Claims validation failed: {0}")]
    ClaimsValidation(String),

    #[error("Decode error: {0}")]
    DecodeError(#[from] DecodeError),

    #[error("Jwt expired at {0}")]
    JwtExpired(String),
}
