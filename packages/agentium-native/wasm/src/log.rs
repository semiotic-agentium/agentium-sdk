// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

use std::cell::RefCell;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry, filter::EnvFilter};
use wasm_bindgen::prelude::*;

use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_futures::js_sys;

// Holds our callback that would be use by our custom tracing suscriber
// to send OTEL data to js side, where our collector lives
thread_local! {
    static SINK: RefCell<Option<js_sys::Function>> = const {RefCell::new(None)};
}

#[derive(Default)]
struct Fields(std::collections::BTreeMap<String, serde_json::Value>);

impl tracing::field::Visit for Fields {
    fn record_i64(&mut self, f: &tracing::field::Field, v: i64) {
        self.0.insert(f.name().to_string(), v.into());
    }
    fn record_u64(&mut self, f: &tracing::field::Field, v: u64) {
        self.0.insert(f.name().to_string(), v.into());
    }
    fn record_bool(&mut self, f: &tracing::field::Field, v: bool) {
        self.0.insert(f.name().to_string(), v.into());
    }
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        self.0.insert(f.name().to_string(), v.into());
    }
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        self.0.insert(f.name().to_string(), format!("{v:?}").into());
    }
}

#[derive(serde::Serialize)]
struct TelemetryEvent {
    kind: &'static str,
    level: &'static str,
    target: String,
    name: Option<String>,
    fields: std::collections::BTreeMap<String, serde_json::Value>,
    ts_ms: f64,
}

struct JsTelemetryLayer;

impl<S> Layer<S> for JsTelemetryLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();

        let mut visitor = Fields::default();
        event.record(&mut visitor);

        let msg = TelemetryEvent {
            kind: "event",
            level: match *meta.level() {
                tracing::Level::ERROR => "error",
                tracing::Level::WARN => "warn",
                tracing::Level::INFO => "info",
                tracing::Level::DEBUG => "debug",
                tracing::Level::TRACE => "trace",
            },
            target: meta.target().to_string(),
            name: Some(meta.name().to_string()),
            fields: visitor.0,
            ts_ms: js_sys::Date::now(),
        };

        if let Ok(js) = serde_wasm_bindgen::to_value(&msg) {
            emit(js);
        }
    }
}

fn emit(msg: JsValue) {
    SINK.with(|sink| {
        if let Some(s) = sink.borrow().as_ref() {
            // this returns a result, just ignore it
            _ = s.call1(&JsValue::NULL, &msg);
        }
    })
}

#[wasm_bindgen]
pub fn init_tracing(sink: js_sys::Function, filter: Option<String>) {
    SINK.with(|s| *s.borrow_mut() = Some(sink));

    let filter = filter
        .as_deref()
        .unwrap_or("info")
        .parse::<EnvFilter>()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = Registry::default().with(filter).with(JsTelemetryLayer);

    let _ = tracing::subscriber::set_global_default(subscriber);
}
