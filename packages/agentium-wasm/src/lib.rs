// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

mod error;
mod log;
mod types;
mod vc;

pub use error::VcError;
pub use types::{
    CredentialSubject, Issuer, JwtClaims, KeyPair, VerifiableCredential, VerificationResult,
};
