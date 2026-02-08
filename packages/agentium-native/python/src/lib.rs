// SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
//
// SPDX-License-Identifier: BUSL-1.1

//! Python bindings for Agentium SDK core functionality.
//!
//! This module exposes JWT-VC verification, DID document parsing,
//! key generation, and telemetry to Python via PyO3.

use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use agentium_sdk_core::{
    DidDocument, JwtRef, KeyPair, PrivateKey, PublicKey, TelemetryEvent, TelemetryLayer,
    TelemetrySink, verify_jwt as core_verify_jwt,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use tracing_subscriber::Registry;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;

/// Structured error for verification failures.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[pyclass(get_all)]
pub struct VerificationError {
    /// Error code (e.g., "JWT_EXPIRED", "VERIFICATION_FAILED")
    pub code: String,
    /// Human-readable error message
    pub message: String,
}

#[pymethods]
impl VerificationError {
    fn __repr__(&self) -> String {
        format!(
            "VerificationError(code='{}', message='{}')",
            self.code, self.message
        )
    }
}

impl From<agentium_sdk_core::VcError> for VerificationError {
    fn from(err: agentium_sdk_core::VcError) -> Self {
        use agentium_sdk_core::VcError;
        let (code, message) = match err {
            VcError::JwtExpired(exp) => {
                ("JWT_EXPIRED".to_string(), format!("JWT expired at {exp}"))
            }
            VcError::InvalidJwt(e) => (
                "INVALID_JWT_FORMAT".to_string(),
                format!("Invalid JWT format: {e}"),
            ),
            VcError::InvalidJwk(s) => ("INVALID_JWK".to_string(), s),
            VcError::VerificationFailed(e) => ("VERIFICATION_FAILED".to_string(), e.to_string()),
            VcError::ClaimsValidation(s) => ("CLAIMS_VALIDATION".to_string(), s),
            VcError::Serialization(e) => ("SERIALIZATION_ERROR".to_string(), e.to_string()),
            VcError::DecodeError(e) => ("DECODE_ERROR".to_string(), e.to_string()),
            VcError::KeyGeneration(e) => ("KEY_GENERATION".to_string(), e.to_string()),
            VcError::SigningFailed(e) => ("SIGNING_FAILED".to_string(), e.to_string()),
        };
        Self { code, message }
    }
}

impl From<agentium_sdk_core::JwtError> for VerificationError {
    fn from(err: agentium_sdk_core::JwtError) -> Self {
        use agentium_sdk_core::JwtError;
        let (code, message) = match err {
            JwtError::Parts => (
                "INVALID_JWT_FORMAT".to_string(),
                "JWT must have exactly 3 dot-separated parts".to_string(),
            ),
            JwtError::Base64(e) => (
                "DECODE_ERROR".to_string(),
                format!("Invalid Base64url: {e}"),
            ),
            JwtError::InvalidClaims(e) => (
                "INVALID_JWT_FORMAT".to_string(),
                format!("Could not deserialize claims: {e}"),
            ),
        };
        Self { code, message }
    }
}

impl From<agentium_sdk_core::SignError> for VerificationError {
    fn from(err: agentium_sdk_core::SignError) -> Self {
        use agentium_sdk_core::SignError;
        let (code, message) = match err {
            SignError::UnsupportedNamespace(ns) => (
                "UNSUPPORTED_NAMESPACE".to_string(),
                format!("Chain namespace not supported for signing: {ns}"),
            ),
            SignError::InvalidKeyLength {
                expected,
                got,
                chain,
            } => (
                "INVALID_KEY_LENGTH".to_string(),
                format!("Invalid key length for {chain}: expected {expected}, got {got}"),
            ),
            SignError::InvalidKeyFormat { chain, reason } => (
                "INVALID_KEY_FORMAT".to_string(),
                format!("Invalid key format for {chain}: {reason}"),
            ),
            SignError::SigningFailed(e) => (
                "SIGNING_FAILED".to_string(),
                format!("Signing operation failed: {e}"),
            ),
        };
        Self { code, message }
    }
}

/// Result of JWT verification.
#[pyclass]
pub struct VerificationResult {
    /// Whether the JWT signature is valid
    #[pyo3(get)]
    pub valid: bool,
    /// JWT claims as Python dict if valid
    #[pyo3(get)]
    pub claims: Option<PyObject>,
    /// Structured error if invalid
    #[pyo3(get)]
    pub error: Option<VerificationError>,
}

#[pymethods]
impl VerificationResult {
    fn __repr__(&self) -> String {
        if self.valid {
            "VerificationResult(valid=True)".to_string()
        } else {
            format!(
                "VerificationResult(valid=False, error={})",
                self.error
                    .as_ref()
                    .map(|e| e.code.as_str())
                    .unwrap_or("None")
            )
        }
    }
}

/// Parsed JWT header.
#[derive(Serialize, Deserialize)]
#[pyclass(get_all)]
pub struct JwtHeader {
    /// Algorithm (e.g., "EdDSA")
    pub alg: String,
    /// Token type (usually "JWT")
    pub typ: Option<String>,
    /// Key ID - references verification method in DID document
    pub kid: Option<String>,
}

#[pymethods]
impl JwtHeader {
    fn __repr__(&self) -> String {
        format!(
            "JwtHeader(alg='{}', typ={:?}, kid={:?})",
            self.alg, self.typ, self.kid
        )
    }
}

/// Generated key pair with private and public keys.
#[pyclass]
pub struct GeneratedKeyPair {
    #[pyo3(get)]
    pub private_key_jwk: String,
    #[pyo3(get)]
    pub public_key_jwk: String,
}

#[pymethods]
impl GeneratedKeyPair {
    fn __repr__(&self) -> String {
        "GeneratedKeyPair(...)".to_string()
    }
}

/// Verify a JWT against a public key.
///
/// Args:
///     jwt: The JWT string to verify (compact format: header.payload.signature)
///     public_key_jwk: The public key as JWK JSON string
///
/// Returns:
///     VerificationResult with validity status and decoded claims as Python dict if valid
#[pyfunction]
pub fn verify_jwt(py: Python<'_>, jwt: &str, public_key_jwk: &str) -> VerificationResult {
    let pubkey: Result<PublicKey, _> = public_key_jwk.try_into();

    let pubkey = match pubkey {
        Ok(pk) => pk,
        Err(e) => {
            return VerificationResult {
                valid: false,
                claims: None,
                error: Some(VerificationError::from(e)),
            };
        }
    };

    match core_verify_jwt(jwt, &pubkey) {
        Ok(claims) => match pythonize::pythonize(py, &claims) {
            Ok(py_claims) => VerificationResult {
                valid: true,
                claims: Some(py_claims.into()),
                error: None,
            },
            Err(e) => VerificationResult {
                valid: false,
                claims: None,
                error: Some(VerificationError {
                    code: "SERIALIZATION_ERROR".to_string(),
                    message: format!("Failed to convert claims to Python: {e}"),
                }),
            },
        },
        Err(err) => VerificationResult {
            valid: false,
            claims: None,
            error: Some(VerificationError::from(err)),
        },
    }
}

/// Parse a JWT header without verifying the signature.
///
/// Args:
///     jwt: The JWT string (compact format: header.payload.signature)
///
/// Returns:
///     JwtHeader containing algorithm, type, and optional key ID
///
/// Raises:
///     ValueError: If the JWT format is invalid
#[pyfunction]
pub fn parse_jwt_header(jwt: &str) -> PyResult<JwtHeader> {
    let jwt_ref = JwtRef::try_from(jwt).map_err(|e| {
        let err: VerificationError = e.into();
        PyValueError::new_err(err.message)
    })?;

    let header = jwt_ref.header_claims().map_err(|e| {
        let err: VerificationError = e.into();
        PyValueError::new_err(err.message)
    })?;

    Ok(JwtHeader {
        alg: header.alg,
        typ: header.typ,
        kid: header.kid,
    })
}

/// Extract the public key JWK from a DID document.
///
/// Args:
///     did_document_json: The DID document as JSON string
///     kid: Optional key ID to match (from JWT header). Can be full ID or just fragment.
///
/// Returns:
///     The public key as JWK JSON string
///
/// Raises:
///     ValueError: If the DID document is invalid or no matching key is found
#[pyfunction]
#[pyo3(signature = (did_document_json, kid=None))]
pub fn extract_public_key_jwk(did_document_json: &str, kid: Option<&str>) -> PyResult<String> {
    let did_document: DidDocument = serde_json::from_str(did_document_json)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let jwk = did_document
        .extract_public_key_jwk(kid)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    serde_json::to_string(jwk).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Generate a new Ed25519 key pair.
///
/// Returns:
///     GeneratedKeyPair with private_key_jwk and public_key_jwk as JSON strings.
///     The private key should be stored securely and never exposed.
///
/// Raises:
///     ValueError: If key generation fails
#[pyfunction]
pub fn generate_keypair() -> PyResult<GeneratedKeyPair> {
    let keypair = KeyPair::new().map_err(|e| PyValueError::new_err(e.to_string()))?;

    let private_key_jwk =
        serde_json::to_string(&keypair).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let public_key_jwk = serde_json::to_string(&keypair.public_jwk())
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    Ok(GeneratedKeyPair {
        private_key_jwk,
        public_key_jwk,
    })
}

/// Extract public key from a private JWK.
///
/// Args:
///     private_key_jwk: The private key as JWK JSON string
///
/// Returns:
///     The public key as JWK JSON string
///
/// Raises:
///     ValueError: If the private key is invalid
#[pyfunction]
pub fn get_public_key(private_key_jwk: &str) -> PyResult<String> {
    let private_key =
        PrivateKey::try_from(private_key_jwk).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let public_key = private_key.pubkey();

    serde_json::to_string(public_key.jwk_key()).map_err(|e| PyValueError::new_err(e.to_string()))
}

use tracing::instrument;

/// Sign a challenge message for wallet authentication.
///
/// The signing algorithm is determined by the chain namespace in the CAIP-2 identifier.
/// For example, `eip155:*` chains use secp256k1 ECDSA with EIP-191 message encoding.
///
/// Args:
///     message: The challenge message bytes from the backend.
///     chain_id: CAIP-2 chain identifier string (e.g., "eip155:84532").
///         See: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md
///     private_key: Raw private key bytes (format depends on chain, 32 bytes for EVM).
///
/// Returns:
///     Hex-encoded signature string (format is chain-specific).
///
/// Raises:
///     ValueError: If chain_id is not a valid CAIP-2 string, key is malformed,
///         namespace is unsupported, or signing fails.
#[pyfunction]
#[instrument(skip(message, private_key), fields(chain_id = chain_id, message_len = message.len()))]
pub fn sign_challenge(message: &[u8], chain_id: &str, private_key: &[u8]) -> PyResult<String> {
    let caip2 = agentium_sdk_core::Caip2::new(chain_id)
        .map_err(|e| PyValueError::new_err(format!("Invalid CAIP-2 chain_id: {e}")))?;

    agentium_sdk_core::sign_challenge(message, &caip2, private_key)
        .map(|sig| sig.into_string())
        .map_err(|e| {
            let err: VerificationError = e.into();
            PyValueError::new_err(format!("[{}] {}", err.code, err.message))
        })
}

/// Validate a CAIP-2 chain identifier string.
///
/// CAIP-2 defines a format for blockchain identifiers: `namespace:reference`
/// - Namespace: 3-8 lowercase alphanumeric characters (e.g., "eip155", "solana")
/// - Reference: 1-32 alphanumeric characters with hyphens/underscores (e.g., "1", "84532")
///
/// See: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md
///
/// Args:
///     chain_id: String to validate (e.g., "eip155:84532", "cosmos:cosmoshub-4")
///
/// Returns:
///     True if valid, False otherwise. Never raises exceptions.
#[pyfunction]
pub fn validate_caip2(chain_id: &str) -> PyResult<bool> {
    Ok(agentium_sdk_core::Caip2::new(chain_id).is_ok())
}

// ============================================================================
// Telemetry Support
// ============================================================================

/// Global storage for the Python callback.
///
/// We use OnceLock + Arc because:
/// - The tracing subscriber is set globally once
/// - The sink needs to be Send + Sync for the Layer trait
/// - Py<PyAny> is Send when not borrowed
static PY_CALLBACK: OnceLock<Arc<PyTelemetrySink>> = OnceLock::new();

/// Python implementation of [`TelemetrySink`].
///
/// Holds a Python callable and forwards telemetry events to it.
struct PyTelemetrySink {
    callback: Py<PyAny>,
}

impl TelemetrySink for PyTelemetrySink {
    fn emit(&self, event: TelemetryEvent) {
        // Acquire GIL to call into Python
        Python::with_gil(|py| {
            // Convert event to Python dict using pythonize
            if let Ok(py_event) = pythonize::pythonize(py, &event) {
                // Call the Python callback, ignore errors
                let _ = self.callback.call1(py, (py_event,));
            }
        });
    }

    fn now_ms(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64() * 1000.0)
            .unwrap_or(0.0)
    }
}

// Py<PyAny> is Send when not borrowed
unsafe impl Send for PyTelemetrySink {}
unsafe impl Sync for PyTelemetrySink {}

/// Initialize tracing with a Python callback sink.
///
/// Args:
///     callback: Python callable that receives telemetry events as dicts.
///               Each event has: kind, level, target, name, fields, ts_ms
///     filter: Optional filter string (e.g., "info", "debug", "agentium=trace").
///             Defaults to "info" if not provided.
///
/// Note:
///     This can only be called once per process. Subsequent calls are ignored.
///
/// Example:
///     ```python
///     def my_handler(event):
///         print(f"[{event['level']}] {event['target']}: {event['fields']}")
///
///     init_tracing(my_handler, "debug")
///     ```
#[pyfunction]
#[pyo3(signature = (callback, filter=None))]
pub fn init_tracing(callback: Py<PyAny>, filter: Option<String>) {
    // Only initialize once
    if PY_CALLBACK.get().is_some() {
        return;
    }

    let sink = Arc::new(PyTelemetrySink { callback });

    // Store globally (ignore if already set - race condition)
    let _ = PY_CALLBACK.set(Arc::clone(&sink));

    let filter = filter
        .as_deref()
        .unwrap_or("info")
        .parse::<EnvFilter>()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // Create layer with Arc-wrapped sink
    let layer = TelemetryLayer::new(ArcSink(sink));
    let subscriber = Registry::default().with(filter).with(layer);

    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Wrapper to impl TelemetrySink for Arc<PyTelemetrySink>
struct ArcSink(Arc<PyTelemetrySink>);

impl TelemetrySink for ArcSink {
    fn emit(&self, event: TelemetryEvent) {
        self.0.emit(event);
    }

    fn now_ms(&self) -> f64 {
        self.0.now_ms()
    }
}

/// Native Rust module for Agentium SDK.
///
/// This module provides low-level cryptographic operations:
/// - JWT verification with Ed25519
/// - JWT header parsing
/// - DID document key extraction
/// - Key pair generation
/// - Telemetry initialization
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VerificationResult>()?;
    m.add_class::<VerificationError>()?;
    m.add_class::<JwtHeader>()?;
    m.add_class::<GeneratedKeyPair>()?;
    m.add_function(wrap_pyfunction!(verify_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(parse_jwt_header, m)?)?;
    m.add_function(wrap_pyfunction!(extract_public_key_jwk, m)?)?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(get_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(init_tracing, m)?)?;
    m.add_function(wrap_pyfunction!(sign_challenge, m)?)?;
    m.add_function(wrap_pyfunction!(validate_caip2, m)?)?;
    Ok(())
}
