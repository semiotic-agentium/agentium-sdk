// SPDX-FileCopyrightText: 2026 Semiotic AI, Inc.
//
// SPDX-License-Identifier: BUSL-1.1

//! WASM telemetry bindings using shared infrastructure from core.

use std::cell::RefCell;

use agentium_sdk_core::{TelemetryEvent, TelemetryLayer, TelemetrySink};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Registry, filter::EnvFilter};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::js_sys;

// Thread-local storage for the JS callback.
// WASM is single-threaded, so we use RefCell for interior mutability.
thread_local! {
    static JS_CALLBACK: RefCell<Option<js_sys::Function>> = const { RefCell::new(None) };
}

/// WASM implementation of [`TelemetrySink`].
///
/// Forwards telemetry events to a JavaScript callback function.
struct WasmTelemetrySink;

impl TelemetrySink for WasmTelemetrySink {
    fn emit(&self, event: TelemetryEvent) {
        JS_CALLBACK.with(|callback| {
            if let Some(func) = callback.borrow().as_ref()
                && let Ok(js_value) = serde_wasm_bindgen::to_value(&event)
            {
                // Ignore call errors - JS side may have issues
                let _ = func.call1(&JsValue::NULL, &js_value);
            }
        });
    }

    fn now_ms(&self) -> f64 {
        js_sys::Date::now()
    }
}

// SAFETY: WASM is single-threaded, these markers are needed for the trait bounds
unsafe impl Send for WasmTelemetrySink {}
unsafe impl Sync for WasmTelemetrySink {}

/// Initialize tracing with a JavaScript callback sink.
///
/// # Arguments
/// * `sink` - JavaScript function that receives telemetry events as objects
/// * `filter` - Optional filter string (e.g., "info", "debug", "agentium=trace")
#[wasm_bindgen]
pub fn init_tracing(sink: js_sys::Function, filter: Option<String>) {
    JS_CALLBACK.with(|s| *s.borrow_mut() = Some(sink));

    let filter = filter
        .as_deref()
        .unwrap_or("info")
        .parse::<EnvFilter>()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let layer = TelemetryLayer::new(WasmTelemetrySink);
    let subscriber = Registry::default().with(filter).with(layer);

    let _ = tracing::subscriber::set_global_default(subscriber);
}
