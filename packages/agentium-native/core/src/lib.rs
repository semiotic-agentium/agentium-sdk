// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

mod error;
mod jwt;
mod key_pair;
mod types;
mod vc;

pub use error::VcError;
pub use jwt::{JwtError, JwtRef};
pub use key_pair::{KeyPair, PrivateKey, PublicKey};
pub use types::{CredentialSubject, Issuer, JwtClaims, VerifiableCredential};
pub use vc::verify_jwt;
