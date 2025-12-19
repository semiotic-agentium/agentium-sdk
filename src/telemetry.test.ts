// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import {
  consoleSink,
  nullSink,
  withLevelFilter,
  withTargetFilter,
  composeSinks,
  type TelemetryEvent,
  type TelemetrySink,
} from './telemetry';

function createEvent(overrides: Partial<TelemetryEvent> = {}): TelemetryEvent {
  return {
    kind: 'event',
    level: 'info',
    target: 'agentium_sdk_core::vc',
    name: 'test_event',
    fields: {},
    ts_ms: Date.now(),
    ...overrides,
  };
}

describe('Telemetry Sinks', () => {
  describe('consoleSink', () => {
    it('logs message and fields to console', () => {
      const spy = vi.spyOn(console, 'info').mockImplementation(() => {});

      const event = createEvent({
        level: 'info',
        target: 'agentium_sdk_core::vc',
        fields: {
          message: 'JWT verification successful',
          issuer: 'did:web:api.agentium.network',
          subject: 'did:pkh:eip155:1:0x1234',
        },
      });

      consoleSink(event);

      expect(spy).toHaveBeenCalledWith('[agentium_sdk_core::vc]', 'JWT verification successful', {
        issuer: 'did:web:api.agentium.network',
        subject: 'did:pkh:eip155:1:0x1234',
      });

      spy.mockRestore();
    });

    it('falls back to event.name when no message field', () => {
      const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});

      const event = createEvent({
        level: 'debug',
        name: 'keypair_generated',
        fields: { algorithm: 'Ed25519' },
      });

      consoleSink(event);

      expect(spy).toHaveBeenCalledWith('[agentium_sdk_core::vc]', 'keypair_generated', {
        algorithm: 'Ed25519',
      });

      spy.mockRestore();
    });

    it('omits fields object when empty', () => {
      const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      const event = createEvent({
        level: 'warn',
        fields: { message: 'Warning message' },
      });

      consoleSink(event);

      expect(spy).toHaveBeenCalledWith('[agentium_sdk_core::vc]', 'Warning message');

      spy.mockRestore();
    });

    it('maps trace level to console.debug', () => {
      const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});

      consoleSink(createEvent({ level: 'trace', fields: { message: 'trace msg' } }));

      expect(spy).toHaveBeenCalled();

      spy.mockRestore();
    });

    it('uses console.error for error level', () => {
      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

      consoleSink(createEvent({ level: 'error', fields: { message: 'error msg' } }));

      expect(spy).toHaveBeenCalled();

      spy.mockRestore();
    });
  });

  describe('nullSink', () => {
    it('does nothing', () => {
      // Should not throw
      expect(() => nullSink(createEvent())).not.toThrow();
    });
  });
});

describe('Telemetry Filters', () => {
  describe('withLevelFilter', () => {
    it('forwards events matching allowed levels', () => {
      const received: TelemetryEvent[] = [];
      const sink: TelemetrySink = (e) => received.push(e);

      const filtered = withLevelFilter(['error', 'warn'], sink);

      filtered(createEvent({ level: 'error' }));
      filtered(createEvent({ level: 'warn' }));
      filtered(createEvent({ level: 'info' }));
      filtered(createEvent({ level: 'debug' }));

      expect(received).toHaveLength(2);
      expect(received[0].level).toBe('error');
      expect(received[1].level).toBe('warn');
    });
  });

  describe('withTargetFilter', () => {
    it('forwards events matching target prefixes', () => {
      const received: TelemetryEvent[] = [];
      const sink: TelemetrySink = (e) => received.push(e);

      const filtered = withTargetFilter(['agentium_sdk'], sink);

      filtered(createEvent({ target: 'agentium_sdk_core::vc' }));
      filtered(createEvent({ target: 'agentium_sdk_wasm::log' }));
      filtered(createEvent({ target: 'other_crate::module' }));

      expect(received).toHaveLength(2);
      expect(received.every((e) => e.target.startsWith('agentium_sdk'))).toBe(true);
    });
  });
});

describe('composeSinks', () => {
  it('forwards events to all sinks', () => {
    const received1: TelemetryEvent[] = [];
    const received2: TelemetryEvent[] = [];

    const composed = composeSinks(
      (e) => received1.push(e),
      (e) => received2.push(e),
    );

    const event = createEvent();
    composed(event);

    expect(received1).toHaveLength(1);
    expect(received2).toHaveLength(1);
    expect(received1[0]).toBe(event);
    expect(received2[0]).toBe(event);
  });

  it('works with filters', () => {
    const errors: TelemetryEvent[] = [];
    const all: TelemetryEvent[] = [];

    const composed = composeSinks(
      withLevelFilter(['error'], (e) => errors.push(e)),
      (e) => all.push(e),
    );

    composed(createEvent({ level: 'info' }));
    composed(createEvent({ level: 'error' }));

    expect(errors).toHaveLength(1);
    expect(all).toHaveLength(2);
  });
});
