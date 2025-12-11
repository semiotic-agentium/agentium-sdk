// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

const STORAGE_KEY = 'agentium:membership_vc';

/**
 * Storage interface for persisting membership VCs.
 */
export interface VcStorage {
  /** Retrieve the stored VC JWT, or null if none exists */
  get(): string | null;
  /** Store a VC JWT */
  set(jwt: string): void;
  /** Remove the stored VC */
  clear(): void;
}

/**
 * Creates a browser storage implementation using LocalStorage.
 * Use this in browser environments.
 *
 * @returns VcStorage implementation backed by LocalStorage
 */
export function createBrowserStorage(): VcStorage {
  return {
    get: () => localStorage.getItem(STORAGE_KEY),
    set: (jwt) => localStorage.setItem(STORAGE_KEY, jwt),
    clear: () => localStorage.removeItem(STORAGE_KEY),
  };
}

/**
 * Creates an in-memory storage implementation.
 * Use this for Node.js environments or testing.
 *
 * @returns VcStorage implementation backed by memory
 */
export function createMemoryStorage(): VcStorage {
  let stored: string | null = null;
  return {
    get: () => stored,
    set: (jwt) => {
      stored = jwt;
    },
    clear: () => {
      stored = null;
    },
  };
}
