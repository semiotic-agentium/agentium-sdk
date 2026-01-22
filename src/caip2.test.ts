// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

import { describe, it, expect } from 'vitest';
import { Caip2, Caip2Error, assertSupportedChain } from './caip2';

describe('Caip2', () => {
  describe('static constants', () => {
    it('should have SUPPORTED_CHAINS array with both chains', () => {
      expect(Caip2.SUPPORTED_CHAINS).toHaveLength(2);
      expect(Caip2.SUPPORTED_CHAINS).toContain(Caip2.BASE_MAINNET);
      expect(Caip2.SUPPORTED_CHAINS).toContain(Caip2.BASE_SEPOLIA);
    });
  });

  describe('parse', () => {
    it('should parse valid CAIP-2 strings', () => {
      const caip2 = Caip2.parse('eip155:8453');
      expect(caip2.namespace).toBe('eip155');
      expect(caip2.reference).toBe('8453');
    });

    it('should parse Base Sepolia', () => {
      const caip2 = Caip2.parse('eip155:84532');
      expect(caip2.namespace).toBe('eip155');
      expect(caip2.reference).toBe('84532');
    });

    it('should parse cosmos chain with hyphen in reference', () => {
      const caip2 = Caip2.parse('cosmos:cosmoshub-4');
      expect(caip2.namespace).toBe('cosmos');
      expect(caip2.reference).toBe('cosmoshub-4');
    });

    it('should throw on empty namespace', () => {
      expect(() => Caip2.parse(':84532')).toThrow(Caip2Error);
      expect(() => Caip2.parse(':84532')).toThrow('at least 3 characters');
    });

    it('should throw on namespace too short', () => {
      expect(() => Caip2.parse('ab:123')).toThrow(Caip2Error);
      expect(() => Caip2.parse('ab:123')).toThrow('at least 3 characters');
    });

    it('should throw on namespace too long', () => {
      expect(() => Caip2.parse('toolongns:123')).toThrow(Caip2Error);
      expect(() => Caip2.parse('toolongns:123')).toThrow('at most 8 characters');
    });

    it('should throw on uppercase namespace', () => {
      expect(() => Caip2.parse('EIP155:1')).toThrow(Caip2Error);
      expect(() => Caip2.parse('EIP155:1')).toThrow('lowercase alphanumeric');
    });

    it('should throw on empty reference', () => {
      expect(() => Caip2.parse('eip155:')).toThrow(Caip2Error);
      expect(() => Caip2.parse('eip155:')).toThrow('cannot be empty');
    });

    it('should throw on reference too long', () => {
      const longRef = 'a'.repeat(33);
      expect(() => Caip2.parse(`eip155:${longRef}`)).toThrow(Caip2Error);
      expect(() => Caip2.parse(`eip155:${longRef}`)).toThrow('at most 32 characters');
    });

    it('should throw on invalid characters in reference', () => {
      expect(() => Caip2.parse('eip155:test@chain')).toThrow(Caip2Error);
      expect(() => Caip2.parse('eip155:test@chain')).toThrow('alphanumeric characters');
    });
  });

  describe('isEvm', () => {
    it('should return true for eip155 namespace', () => {
      expect(Caip2.BASE_MAINNET.isEvm()).toBe(true);
      expect(Caip2.BASE_SEPOLIA.isEvm()).toBe(true);
      expect(Caip2.parse('eip155:1').isEvm()).toBe(true);
    });

  });

  describe('evmChainId', () => {
    it('should return numeric chain ID for EVM chains', () => {
      expect(Caip2.BASE_MAINNET.evmChainId()).toBe(8453);
      expect(Caip2.BASE_SEPOLIA.evmChainId()).toBe(84532);
      expect(Caip2.parse('eip155:1').evmChainId()).toBe(1);
    });

    it('should throw for non-EVM chains', () => {
      const cosmos = Caip2.parse('cosmos:cosmoshub-4');
      expect(() => cosmos.evmChainId()).toThrow(Caip2Error);
      expect(() => cosmos.evmChainId()).toThrow('Not an EVM chain');
    });

  });

  describe('isSupported', () => {
    it('should return true for BASE_MAINNET', () => {
      expect(Caip2.BASE_MAINNET.isSupported()).toBe(true);
    });

    it('should return false for other chains', () => {
      expect(Caip2.parse('cosmos:cosmoshub-4').isSupported()).toBe(false);
      expect(Caip2.parse('solana:mainnet').isSupported()).toBe(false);
      expect(Caip2.parse('eip155:137').isSupported()).toBe(false); // Polygon
    });
  });

  describe('toString', () => {
    it('should return CAIP-2 string format', () => {
      expect(Caip2.BASE_MAINNET.toString()).toBe('eip155:8453');
      expect(Caip2.BASE_SEPOLIA.toString()).toBe('eip155:84532');
      expect(Caip2.parse('cosmos:cosmoshub-4').toString()).toBe('cosmos:cosmoshub-4');
    });
  });

  describe('equals', () => {
    it('should return true for equal chains', () => {
      expect(Caip2.BASE_MAINNET.equals(Caip2.parse('eip155:8453'))).toBe(true);
      expect(Caip2.BASE_SEPOLIA.equals(Caip2.parse('eip155:84532'))).toBe(true);
    });

    it('should return false for different chains', () => {
      expect(Caip2.BASE_MAINNET.equals(Caip2.BASE_SEPOLIA)).toBe(false);
      expect(Caip2.BASE_MAINNET.equals(Caip2.parse('eip155:1'))).toBe(false);
    });
  });
});

describe('assertSupportedChain', () => {
  it('should not throw for supported chains', () => {
    expect(() => assertSupportedChain(Caip2.BASE_MAINNET)).not.toThrow();
    expect(() => assertSupportedChain(Caip2.BASE_SEPOLIA)).not.toThrow();
    expect(() => assertSupportedChain(Caip2.parse('eip155:8453'))).not.toThrow();
    expect(() => assertSupportedChain(Caip2.parse('eip155:84532'))).not.toThrow();
  });

  it('should throw for unsupported chains', () => {
    expect(() => assertSupportedChain(Caip2.parse('eip155:1'))).toThrow(Caip2Error);
    expect(() => assertSupportedChain(Caip2.parse('eip155:1'))).toThrow('Unsupported chain');
  });

});
