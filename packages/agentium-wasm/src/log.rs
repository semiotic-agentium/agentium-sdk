// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

use std::sync::Once;

use tracing::info;
use wasm_bindgen::prelude::wasm_bindgen;

/// Initialize logging for the WASM module.
///
/// This sets up `tracing` to output to the browser console via `tracing-wasm`.
/// Call this once before using any other functions from this library.
#[wasm_bindgen]
pub fn init_logging() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        console_error_panic_hook::set_once();

        let config = tracing_wasm::WASMLayerConfigBuilder::new()
            .set_max_level(tracing::Level::DEBUG)
            .build();

        tracing_wasm::set_as_global_default_with_config(config);

        info!("WASM logging initialized");
    });
}
