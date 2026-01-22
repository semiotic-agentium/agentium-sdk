// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT

/**
 * Response from wallet challenge request.
 */
export interface WalletChallengeResponse {
  /** SIWE message to sign */
  message: string;
  /** Unique nonce for replay protection */
  nonce: string;
}

/**
 * Function type for wallet message signing.
 * User provides this - SDK calls it when signature is needed.
 *
 * @param message - The SIWE message to sign
 * @returns Hex-encoded signature (0x-prefixed)
 *
 * @example
 * ```typescript
 * // With MetaMask
 * const signer: MessageSigner = (msg) =>
 *   window.ethereum.request({
 *     method: 'personal_sign',
 *     params: [msg, address]
 *   });
 *
 * // With wagmi
 * const signer: MessageSigner = (msg) =>
 *   signMessageAsync({ message: msg });
 * ```
 */
export type MessageSigner = (message: string) => Promise<string>;
