// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

mod caip2;
mod did;
mod error;
mod jwt;
mod key_pair;
pub mod signer;
pub mod telemetry;
mod types;
mod vc;

pub use caip2::{Caip2, Caip2Error, ChainNamespace, NamespaceError, ReferenceError};
pub use signer::{sign_challenge, SignError, WalletSignature};
pub use did::{Did, DidDocument, DidParseError, JsonWebKey, KeyId, VerificationMethod};
pub use error::VcError;
pub use jwt::{JwtError, JwtHeader, JwtRef};
pub use key_pair::{KeyPair, PrivateKey, PublicKey};
pub use telemetry::{TelemetryEvent, TelemetryLayer, TelemetrySink};
pub use types::{CredentialSubject, Issuer, JwtClaims, VerifiableCredential};
pub use vc::verify_jwt;
