// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use ssi::jwk::JWK;

use crate::VcError;

/// Key pair containing both private and public JWK
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPair {
    /// Full JWK with private key material (keep secret!)
    private_key: PrivateKey,
    /// Public JWK (safe to share)
    public_key: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey(JWK);

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrivateKey(JWK);

impl KeyPair {
    // Note:
    // This never fails as long as ring feature from the
    // ssi crate is set
    pub fn new() -> Result<KeyPair, VcError> {
        Self::generate_keypair()
    }

    fn generate_keypair() -> Result<KeyPair, VcError> {
        let jwk = JWK::generate_ed25519()?;
        let public_jwk = jwk.to_public();

        Ok(KeyPair {
            private_key: PrivateKey(jwk),
            public_key: PublicKey(public_jwk),
        })
    }

    pub fn public_jwk(&self) -> JWK {
        self.public_key.0.clone()
    }
}

impl PublicKey {
    pub fn jwk_key(&self) -> &JWK {
        &self.0
    }
}

impl PrivateKey {
    pub fn pubkey(&self) -> PublicKey {
        PublicKey(self.0.to_public())
    }
}

impl TryFrom<&str> for KeyPair {
    type Error = VcError;

    // Where value is a serialized private key
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let private_key = PrivateKey(serde_json::from_str(value)?);
        let public_key = PublicKey(private_key.0.to_public());

        Ok(Self {
            private_key,
            public_key,
        })
    }
}

impl From<PrivateKey> for KeyPair {
    fn from(private_key: PrivateKey) -> KeyPair {
        let public_key = PublicKey(private_key.0.to_public());
        Self {
            private_key,
            public_key,
        }
    }
}

impl TryFrom<&str> for PrivateKey {
    type Error = VcError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let key = serde_json::from_str(value)?;
        Ok(PrivateKey(key))
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(value: PrivateKey) -> Self {
        value.pubkey()
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(value: &PrivateKey) -> Self {
        value.pubkey()
    }
}

impl TryFrom<&str> for PublicKey {
    type Error = VcError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let jwk: JWK = serde_json::from_str(value)?;
        Ok(PublicKey(jwk))
    }
}
