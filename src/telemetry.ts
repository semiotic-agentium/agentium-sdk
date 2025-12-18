// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import { init_tracing as wasmInitTracing } from '../packages/agentium-native/wasm/pkg/agentium_sdk_wasm.js';
import { ensureWasmReady } from './wasm.js';

// ─────────────────────────────────────────────────────────────────────────────
// Types (matches Rust TelemetryEvent structure)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Log levels emitted by the WASM telemetry layer.
 */
export type TelemetryLevel = 'error' | 'warn' | 'info' | 'debug' | 'trace';

/**
 * Telemetry event structure as serialized from Rust.
 * This is the shape of events passed to sink callbacks.
 */
export interface TelemetryEvent {
  /** Event kind (currently always "event") */
  kind: 'event';
  /** Log level */
  level: TelemetryLevel;
  /** Module/crate target (e.g., "agentium_sdk_wasm::vc") */
  target: string;
  /** Event name (from tracing span/event) */
  name?: string;
  /** Structured fields from the tracing event */
  fields: Record<string, unknown>;
  /** Timestamp in milliseconds (from JS Date.now()) */
  ts_ms: number;
}

/**
 * A sink receives telemetry events and handles them (log, send to service, etc.).
 */
export type TelemetrySink = (event: TelemetryEvent) => void;

// ─────────────────────────────────────────────────────────────────────────────
// Built-in Sinks
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Console sink that logs events to the browser/Node console.
 * Uses appropriate console method based on level (console.error, console.warn, etc.).
 */
export const consoleSink: TelemetrySink = (event) => {
  const method = event.level === 'trace' ? 'debug' : event.level;
  const consoleFn = console[method] ?? console.log;
  const prefix = `[${event.target}]`;

  // Format message from fields if present
  const message = event.fields['message'] ?? event.name ?? '';
  const otherFields = Object.fromEntries(
    Object.entries(event.fields).filter(([k]) => k !== 'message'),
  );

  if (Object.keys(otherFields).length > 0) {
    consoleFn(prefix, message, otherFields);
  } else {
    consoleFn(prefix, message);
  }
};

/**
 * No-op sink that discards all events.
 * Useful for explicitly disabling telemetry output.
 */
export const nullSink: TelemetrySink = () => {
  // Intentionally empty
};

// ─────────────────────────────────────────────────────────────────────────────
// Composable Utilities
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Wraps a sink with a level filter.
 * Only events matching one of the specified levels are forwarded.
 *
 * @param levels - Array of levels to allow through
 * @param sink - The sink to forward matching events to
 * @returns Filtered sink
 *
 * @example
 * ```ts
 * // Only log errors and warnings to console
 * const errorSink = withLevelFilter(['error', 'warn'], consoleSink);
 * ```
 */
export function withLevelFilter(levels: TelemetryLevel[], sink: TelemetrySink): TelemetrySink {
  const levelSet = new Set(levels);
  return (event) => {
    if (levelSet.has(event.level)) {
      sink(event);
    }
  };
}

/**
 * Wraps a sink with a target filter.
 * Only events whose target starts with one of the specified prefixes are forwarded.
 *
 * @param prefixes - Array of target prefixes to allow
 * @param sink - The sink to forward matching events to
 * @returns Filtered sink
 *
 * @example
 * ```ts
 * // Only log events from agentium modules
 * const agentiumSink = withTargetFilter(['agentium_sdk'], consoleSink);
 * ```
 */
export function withTargetFilter(prefixes: string[], sink: TelemetrySink): TelemetrySink {
  return (event) => {
    if (prefixes.some((prefix) => event.target.startsWith(prefix))) {
      sink(event);
    }
  };
}

/**
 * Composes multiple sinks into a single sink.
 * Each event is forwarded to all sinks in order.
 *
 * @param sinks - Array of sinks to compose
 * @returns Combined sink
 *
 * @example
 * ```ts
 * const sink = composeSinks(
 *   withLevelFilter(['error', 'warn', 'info'], consoleSink),
 *   myPrometheusSink,
 *   myAnalyticsSink
 * );
 * ```
 */
export function composeSinks(...sinks: TelemetrySink[]): TelemetrySink {
  return (event) => {
    for (const sink of sinks) {
      sink(event);
    }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialization
// ─────────────────────────────────────────────────────────────────────────────

let telemetryInitialized = false;

/**
 * Options for initializing telemetry.
 */
export interface InitTelemetryOptions {
  /**
   * The sink to receive telemetry events.
   * Use composeSinks() to combine multiple sinks.
   */
  sink: TelemetrySink;

  /**
   * Tracing filter directive (e.g., "info", "debug", "agentium_sdk=trace").
   * Uses tracing-subscriber's EnvFilter syntax.
   * @default "info"
   */
  filter?: string;
}

/**
 * Initializes WASM telemetry with the provided sink.
 *
 * This must be called after ensureWasmReady() and can only be called once.
 * If not called, no telemetry is emitted (silent by default).
 *
 * @param options - Telemetry configuration
 *
 * @example
 * ```ts
 * import { ensureWasmReady, initTelemetry, consoleSink, withLevelFilter, composeSinks } from 'agentium-sdk';
 *
 * await ensureWasmReady();
 *
 * // Simple: log everything to console
 * initTelemetry({ sink: consoleSink });
 *
 * // Advanced: filter and compose
 * initTelemetry({
 *   sink: composeSinks(
 *     withLevelFilter(['error', 'warn', 'info'], consoleSink),
 *     myCustomSink
 *   ),
 *   filter: 'agentium_sdk=debug'
 * });
 * ```
 */
export async function initTelemetry(options: InitTelemetryOptions): Promise<void> {
  if (telemetryInitialized) {
    console.warn('[Agentium] Telemetry already initialized, ignoring subsequent call');
    return;
  }

  await ensureWasmReady();

  // Wrap the sink to handle the raw JsValue from WASM
  const wrappedSink = (rawEvent: unknown) => {
    // The event comes as a plain object from serde_wasm_bindgen
    options.sink(rawEvent as TelemetryEvent);
  };

  wasmInitTracing(wrappedSink, options.filter ?? null);
  telemetryInitialized = true;
}
