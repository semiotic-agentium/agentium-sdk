// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

//! Shared telemetry infrastructure for Agentium SDK bindings.
//!
//! This module provides a platform-agnostic tracing layer that can be used
//! by different language bindings (WASM, Python, etc.) to capture telemetry
//! events and forward them to their respective runtimes.

use std::collections::BTreeMap;

use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// A telemetry event captured from tracing.
#[derive(Debug, Clone, Serialize)]
pub struct TelemetryEvent {
    /// Event kind (e.g., "event", "span_enter", "span_exit")
    pub kind: &'static str,
    /// Log level ("error", "warn", "info", "debug", "trace")
    pub level: &'static str,
    /// The target/module path
    pub target: String,
    /// Event or span name
    pub name: Option<String>,
    /// Structured fields from the event
    pub fields: BTreeMap<String, serde_json::Value>,
    /// Timestamp in milliseconds (provided by the binding)
    pub ts_ms: f64,
}

/// Trait for sinks that receive telemetry events.
///
/// Each binding implements this to forward events to their runtime
/// (e.g., JS callback, Python callable).
pub trait TelemetrySink: Send + Sync {
    /// Emit a telemetry event to the sink.
    fn emit(&self, event: TelemetryEvent);

    /// Get the current timestamp in milliseconds.
    ///
    /// Each platform provides its own implementation:
    /// - WASM: `js_sys::Date::now()`
    /// - Python: `time.time() * 1000`
    /// - Native: `std::time::SystemTime`
    fn now_ms(&self) -> f64;
}

/// Field visitor that collects tracing fields into a BTreeMap.
#[derive(Default)]
pub struct Fields(pub BTreeMap<String, serde_json::Value>);

impl Visit for Fields {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_string(), value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_string(), value.into());
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        // JSON doesn't support i128, store as string
        self.0
            .insert(field.name().to_string(), value.to_string().into());
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.0
            .insert(field.name().to_string(), value.to_string().into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_string(), value.into());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}").into());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.0
            .insert(field.name().to_string(), value.to_string().into());
    }
}

/// Convert tracing level to string.
fn level_str(level: &tracing::Level) -> &'static str {
    match *level {
        tracing::Level::ERROR => "error",
        tracing::Level::WARN => "warn",
        tracing::Level::INFO => "info",
        tracing::Level::DEBUG => "debug",
        tracing::Level::TRACE => "trace",
    }
}

/// A tracing layer that forwards events to a [`TelemetrySink`].
pub struct TelemetryLayer<S> {
    sink: S,
}

impl<S> TelemetryLayer<S>
where
    S: TelemetrySink,
{
    /// Create a new telemetry layer with the given sink.
    pub fn new(sink: S) -> Self {
        Self { sink }
    }
}

impl<S, Sub> Layer<Sub> for TelemetryLayer<S>
where
    S: TelemetrySink + 'static,
    Sub: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, Sub>) {
        let meta = event.metadata();

        let mut visitor = Fields::default();
        event.record(&mut visitor);

        let telemetry_event = TelemetryEvent {
            kind: "event",
            level: level_str(meta.level()),
            target: meta.target().to_string(),
            name: Some(meta.name().to_string()),
            fields: visitor.0,
            ts_ms: self.sink.now_ms(),
        };

        self.sink.emit(telemetry_event);
    }
}
