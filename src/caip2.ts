// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

/**
 * Error thrown when CAIP-2 parsing or validation fails.
 */
export class Caip2Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Caip2Error';
  }
}

/**
 * CAIP-2 chain identifier (e.g., "eip155:84532", "eip155:8453").
 *
 * CAIP-2 defines a format for blockchain identifiers: `namespace:reference`
 * - Namespace: 3-8 lowercase alphanumeric characters + hyphens
 * - Reference: 1-32 alphanumeric characters + hyphens + underscores
 *
 * @see https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md
 *
 * @example
 * ```typescript
 * const chain = Caip2.parse('eip155:8453');
 * console.log(chain.namespace); // 'eip155'
 * console.log(chain.reference); // '8453'
 * console.log(chain.toString()); // 'eip155:8453'
 * console.log(chain.evmChainId()); // 8453
 *
 * // Use pre-defined constants
 * const base = Caip2.BASE_MAINNET;
 * const baseSepolia = Caip2.BASE_SEPOLIA;
 * ```
 */
export class Caip2 {
  /** Base Sepolia testnet (chain ID 84532) */
  static readonly BASE_SEPOLIA = new Caip2('eip155', '84532');

  /** Base mainnet (chain ID 8453) */
  static readonly BASE_MAINNET = new Caip2('eip155', '8453');

  /** All supported chains for wallet authentication */
  static readonly SUPPORTED_CHAINS: readonly Caip2[] = [Caip2.BASE_MAINNET, Caip2.BASE_SEPOLIA];

  readonly namespace: string;
  readonly reference: string;

  private constructor(namespace: string, reference: string) {
    this.namespace = namespace;
    this.reference = reference;
  }

  /**
   * Parse a CAIP-2 string into a Caip2 instance.
   * @param chainId - CAIP-2 string (e.g., "eip155:8453")
   * @throws {Caip2Error} If the string is not valid CAIP-2 format
   */
  static parse(chainId: string): Caip2 {
    if (!chainId.includes(':')) {
      throw new Caip2Error('CAIP-2 identifier must contain colon separator');
    }

    const colonIndex = chainId.indexOf(':');
    const namespace = chainId.slice(0, colonIndex);
    const reference = chainId.slice(colonIndex + 1);

    // Validate namespace: 3-8 lowercase alphanumeric + hyphens
    if (namespace.length < 3) {
      throw new Caip2Error('namespace must be at least 3 characters');
    }
    if (namespace.length > 8) {
      throw new Caip2Error('namespace must be at most 8 characters');
    }
    if (!/^[a-z0-9-]+$/.test(namespace)) {
      throw new Caip2Error(
        'namespace must contain only lowercase alphanumeric characters and hyphens',
      );
    }

    // Validate reference: 1-32 alphanumeric + hyphens + underscores
    if (reference.length === 0) {
      throw new Caip2Error('reference cannot be empty');
    }
    if (reference.length > 32) {
      throw new Caip2Error('reference must be at most 32 characters');
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(reference)) {
      throw new Caip2Error(
        'reference must contain only alphanumeric characters, hyphens, and underscores',
      );
    }

    return new Caip2(namespace, reference);
  }

  /**
   * Check if this is an EVM chain (eip155 namespace).
   */
  isEvm(): boolean {
    return this.namespace === 'eip155';
  }

  /**
   * Get the numeric EVM chain ID.
   * @throws {Caip2Error} If not an EVM chain or reference is not numeric
   */
  evmChainId(): number {
    if (!this.isEvm()) {
      throw new Caip2Error(`Not an EVM chain: ${this.namespace}`);
    }
    const id = parseInt(this.reference, 10);
    if (isNaN(id)) {
      throw new Caip2Error(`Chain reference is not numeric: ${this.reference}`);
    }
    return id;
  }

  /**
   * Check if this chain is in the supported list.
   */
  isSupported(): boolean {
    return Caip2.SUPPORTED_CHAINS.some(
      (c) => c.namespace === this.namespace && c.reference === this.reference,
    );
  }

  /**
   * Returns the CAIP-2 string representation.
   */
  toString(): string {
    return `${this.namespace}:${this.reference}`;
  }

  /**
   * Check equality with another Caip2 instance.
   */
  equals(other: Caip2): boolean {
    return this.namespace === other.namespace && this.reference === other.reference;
  }
}

/**
 * Validates that a Caip2 is one of the supported chains.
 * @throws {Caip2Error} If chain is not supported
 */
export function assertSupportedChain(caip2: Caip2): void {
  if (!caip2.isSupported()) {
    const supported = Caip2.SUPPORTED_CHAINS.map((c) => c.toString()).join(', ');
    throw new Caip2Error(`Unsupported chain: ${caip2.toString()}. Supported chains: ${supported}`);
  }
}
