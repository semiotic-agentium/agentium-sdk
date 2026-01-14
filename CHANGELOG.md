<!--
SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.

SPDX-License-Identifier: MIT
-->

# Changelog

## [0.9.4](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.9.3...agentium-sdk-v0.9.4) (2026-01-14)


### Bug Fixes

* **python:** fix wheel builds with updated macOS runner and vendored OpenSSL ([e5e7292](https://github.com/semiotic-agentium/agentium-sdk/commit/e5e7292b79c3e30eb387806d0edb7472e7259d79))
* **python:** trigger release to test wheel build fixes ([100cefc](https://github.com/semiotic-agentium/agentium-sdk/commit/100cefc6aaf6a62a912e3c71b3813d8bb64e050b))
* **python:** trigger release to test wheel build fixes ([e6110f8](https://github.com/semiotic-agentium/agentium-sdk/commit/e6110f833c1f0bf4298d673e8125205f8c714669))

## [0.9.3](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.9.2...agentium-sdk-v0.9.3) (2026-01-14)


### Bug Fixes

* **python:** trigger release with corrected wheel build configuration ([c80f5f3](https://github.com/semiotic-agentium/agentium-sdk/commit/c80f5f3c3b4f96dc0ae1231884131d55867e8e25))

## [0.9.2](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.9.1...agentium-sdk-v0.9.2) (2026-01-14)


### Bug Fixes

* **ci:** improve Python wheel build reliability ([4b7b890](https://github.com/semiotic-agentium/agentium-sdk/commit/4b7b8904c6bd5f56d451ed02e5bbb29e3a3a3b9c))
* **ci:** pin Python to 3.13 in our wheels builder ([e2b7f99](https://github.com/semiotic-agentium/agentium-sdk/commit/e2b7f9932214ab6937aac310287a1aa9d717c59c))

## [0.9.1](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.9.0...agentium-sdk-v0.9.1) (2026-01-14)


### Bug Fixes

* use distinct tag prefix for Python releases ([38a60f6](https://github.com/semiotic-agentium/agentium-sdk/commit/38a60f6b6abda13fae9bd32a50f792204e90af9b))

## [0.9.0](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.8.0...agentium-sdk-v0.9.0) (2026-01-14)


### Features

* add PyO3 native bindings for agentium-sdk ([71cf961](https://github.com/semiotic-agentium/agentium-sdk/commit/71cf9616a2ebe44aaeb14d47c52177a2e4f66941))
* add Python SDK interface for Agentium Network ([fbf83b2](https://github.com/semiotic-agentium/agentium-sdk/commit/fbf83b2f802eec36b2cfa739ba554f70a6be7eee))
* add telemetry primitives to core crate ([36c6359](https://github.com/semiotic-agentium/agentium-sdk/commit/36c6359e83462c9d48323243de50f09c10058354))
* **core:** add wallet signing and CAIP-2 support ([22e6ec0](https://github.com/semiotic-agentium/agentium-sdk/commit/22e6ec076d1b79ff0d442e3fc1eaaf5bf6c4be5a))
* **native:** move JWT header parsing and DID key extraction to wasm-rust ([a6c504d](https://github.com/semiotic-agentium/agentium-sdk/commit/a6c504d4bd50a9cfc7aa9cc735fc162fa4c04b9c))
* **python:** expose wallet authentication bindings ([6e53d84](https://github.com/semiotic-agentium/agentium-sdk/commit/6e53d84935690d0a700b5310ee77a383403bfb22))
* return claims as native Python dict via pythonize ([ea8624f](https://github.com/semiotic-agentium/agentium-sdk/commit/ea8624faca6558b4024815aeb0175d979a3322f5))
* SDK improvements and rename to agentium-sdk ([9c55a7f](https://github.com/semiotic-agentium/agentium-sdk/commit/9c55a7fab355d236e41fd942477ef0f57b2f0531))
* **sdk:** add wallet sign-in authentication methods ([04122c4](https://github.com/semiotic-agentium/agentium-sdk/commit/04122c48ba092247c9651e5462d1dd65fb71e084))


### Bug Fixes

* **python:** resolve mypy type errors ([aec6ca7](https://github.com/semiotic-agentium/agentium-sdk/commit/aec6ca78070e20952b00193f8b06a3d5ad15e627))

## [0.8.0](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.7.0...agentium-sdk-v0.8.0) (2025-12-19)


### Features

* add wasmUrl option to AgentiumClient constructor ([a29c076](https://github.com/semiotic-agentium/agentium-sdk/commit/a29c076ae71b519338fac6398260bcd0fedd5ac9))


### Bug Fixes

* remove unused exchangePrivyToken method ([27d70f9](https://github.com/semiotic-agentium/agentium-sdk/commit/27d70f969cff1e611e3b6d49e2b94bacee5c396b))

## [0.7.0](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.6.0...agentium-sdk-v0.7.0) (2025-12-19)


### Features

* add composable telemetry module with sink utilities ([a1354f3](https://github.com/semiotic-agentium/agentium-sdk/commit/a1354f3b8208b4f16d6a584683f54704577360de))
* implement custom telemetry layer with JS sink callback ([ff07a5a](https://github.com/semiotic-agentium/agentium-sdk/commit/ff07a5a0ff2fa5a48394609be9b876330326648d))

## [0.6.0](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.5.2...agentium-sdk-v0.6.0) (2025-12-18)


### Features

* add wasm-url helper for easier WASM initialization ([75c2e15](https://github.com/semiotic-agentium/agentium-sdk/commit/75c2e159413ecd589b6de6554733d08cce23658a))

## [0.5.2](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.5.1...agentium-sdk-v0.5.2) (2025-12-18)


### Bug Fixes

* update credential API to match backend response format ([89a3a26](https://github.com/semiotic-agentium/agentium-sdk/commit/89a3a2661cea0e2e28854b7bb6039d276defd02c))

## [0.5.1](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.5.0...agentium-sdk-v0.5.1) (2025-12-18)


### Bug Fixes

* include wasm in npm package by removing pkg/.gitignore ([22a7f18](https://github.com/semiotic-agentium/agentium-sdk/commit/22a7f189708353871b53f1e672619f21dce96b3c))

## [0.5.0](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.4.0...agentium-sdk-v0.5.0) (2025-12-18)


### ⚠ BREAKING CHANGES

* connectGoogleIdentity response structure changed

### Features

* add agentium-native workspace with core and wasm crates ([d1b82e7](https://github.com/semiotic-agentium/agentium-sdk/commit/d1b82e7ad0b1cddc48675e7bd0cb768e525bfd26))
* add agentium-wasm crate for JWT-VC verification ([bb0fcc2](https://github.com/semiotic-agentium/agentium-sdk/commit/bb0fcc287235281f859defc0136cc85acbc27b81))
* add TypeScript wrapper for WASM initialization ([48261e0](https://github.com/semiotic-agentium/agentium-sdk/commit/48261e0e232335cbecdccebd8267b092ffdca16d))
* add VC types and storage abstraction ([29f3bc7](https://github.com/semiotic-agentium/agentium-sdk/commit/29f3bc747373cf86aca99277f67bd078680e0a9e))
* align SDK types with W3C VC spec and backend SSI implementation ([b448dc4](https://github.com/semiotic-agentium/agentium-sdk/commit/b448dc465e3dd3f1bb8227330d34726e60eb759f))
* implement initial AgentiumClient class ([092dd48](https://github.com/semiotic-agentium/agentium-sdk/commit/092dd48ef8592106c408de7e25c53bb89abde13d))
* integrate VC verification into AgentiumClient ([26b7000](https://github.com/semiotic-agentium/agentium-sdk/commit/26b7000cfec3ccec0530b84df6c030ad51441d98))
* migrate to OAuth 2.0 token endpoint ([ac70a97](https://github.com/semiotic-agentium/agentium-sdk/commit/ac70a97a51efc6977feba9feb4bbbb635e544e5b))
* structured errors in VerificationResult; restore non-throwing verify_jwt ([39aa828](https://github.com/semiotic-agentium/agentium-sdk/commit/39aa828f48283bfa66d5ba3cdafe49f870feb9ae))
* use axios to fetch from identity/connect ([7880bf6](https://github.com/semiotic-agentium/agentium-sdk/commit/7880bf6dc52a705d2903a86abb199a6fddf2c77e))


### Bug Fixes

* add missing exports ([fe7a56a](https://github.com/semiotic-agentium/agentium-sdk/commit/fe7a56adc8cca3605a467108f2f51083d44e8a70))
* bundle wasm in node_modules for git installs ([aa324fd](https://github.com/semiotic-agentium/agentium-sdk/commit/aa324fd78ac57daa76b099b60e568e9ba8d22d5e))
* disable wasm-opt to fix wasm build ([6f2beed](https://github.com/semiotic-agentium/agentium-sdk/commit/6f2beed580892d896797846b116f22937a5867aa))
* update vitest setup to use relative wasm import ([e473447](https://github.com/semiotic-agentium/agentium-sdk/commit/e473447f1585da06508b9a1af69e53aa09e7294e))
* use relative import for wasm to fix npm consumers ([e473447](https://github.com/semiotic-agentium/agentium-sdk/commit/e473447f1585da06508b9a1af69e53aa09e7294e))
* use relative import for wasm to fix npm consumers ([16b5785](https://github.com/semiotic-agentium/agentium-sdk/commit/16b5785f134cd6f3bd04d07f58f2d295b930ed76))
* validate JWT has exactly 3 parts ([531067a](https://github.com/semiotic-agentium/agentium-sdk/commit/531067a72fc88661f70ca2bb70193e431ff90d76))

## [0.4.0](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.3.0...agentium-sdk-v0.4.0) (2025-12-17)


### ⚠ BREAKING CHANGES

* connectGoogleIdentity response structure changed

### Features

* add agentium-native workspace with core and wasm crates ([d1b82e7](https://github.com/semiotic-agentium/agentium-sdk/commit/d1b82e7ad0b1cddc48675e7bd0cb768e525bfd26))
* add agentium-wasm crate for JWT-VC verification ([bb0fcc2](https://github.com/semiotic-agentium/agentium-sdk/commit/bb0fcc287235281f859defc0136cc85acbc27b81))
* add TypeScript wrapper for WASM initialization ([48261e0](https://github.com/semiotic-agentium/agentium-sdk/commit/48261e0e232335cbecdccebd8267b092ffdca16d))
* add VC types and storage abstraction ([29f3bc7](https://github.com/semiotic-agentium/agentium-sdk/commit/29f3bc747373cf86aca99277f67bd078680e0a9e))
* align SDK types with W3C VC spec and backend SSI implementation ([b448dc4](https://github.com/semiotic-agentium/agentium-sdk/commit/b448dc465e3dd3f1bb8227330d34726e60eb759f))
* implement initial AgentiumClient class ([092dd48](https://github.com/semiotic-agentium/agentium-sdk/commit/092dd48ef8592106c408de7e25c53bb89abde13d))
* integrate VC verification into AgentiumClient ([26b7000](https://github.com/semiotic-agentium/agentium-sdk/commit/26b7000cfec3ccec0530b84df6c030ad51441d98))
* migrate to OAuth 2.0 token endpoint ([ac70a97](https://github.com/semiotic-agentium/agentium-sdk/commit/ac70a97a51efc6977feba9feb4bbbb635e544e5b))
* structured errors in VerificationResult; restore non-throwing verify_jwt ([39aa828](https://github.com/semiotic-agentium/agentium-sdk/commit/39aa828f48283bfa66d5ba3cdafe49f870feb9ae))
* use axios to fetch from identity/connect ([7880bf6](https://github.com/semiotic-agentium/agentium-sdk/commit/7880bf6dc52a705d2903a86abb199a6fddf2c77e))


### Bug Fixes

* add missing exports ([fe7a56a](https://github.com/semiotic-agentium/agentium-sdk/commit/fe7a56adc8cca3605a467108f2f51083d44e8a70))
* disable wasm-opt to fix wasm build ([6f2beed](https://github.com/semiotic-agentium/agentium-sdk/commit/6f2beed580892d896797846b116f22937a5867aa))
* validate JWT has exactly 3 parts ([531067a](https://github.com/semiotic-agentium/agentium-sdk/commit/531067a72fc88661f70ca2bb70193e431ff90d76))

## [0.3.0](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.2.1...agentium-sdk-v0.3.0) (2025-12-17)


### ⚠ BREAKING CHANGES

* connectGoogleIdentity response structure changed

### Features

* add agentium-native workspace with core and wasm crates ([d1b82e7](https://github.com/semiotic-agentium/agentium-sdk/commit/d1b82e7ad0b1cddc48675e7bd0cb768e525bfd26))
* add agentium-wasm crate for JWT-VC verification ([bb0fcc2](https://github.com/semiotic-agentium/agentium-sdk/commit/bb0fcc287235281f859defc0136cc85acbc27b81))
* add TypeScript wrapper for WASM initialization ([48261e0](https://github.com/semiotic-agentium/agentium-sdk/commit/48261e0e232335cbecdccebd8267b092ffdca16d))
* add VC types and storage abstraction ([29f3bc7](https://github.com/semiotic-agentium/agentium-sdk/commit/29f3bc747373cf86aca99277f67bd078680e0a9e))
* align SDK types with W3C VC spec and backend SSI implementation ([b448dc4](https://github.com/semiotic-agentium/agentium-sdk/commit/b448dc465e3dd3f1bb8227330d34726e60eb759f))
* integrate VC verification into AgentiumClient ([26b7000](https://github.com/semiotic-agentium/agentium-sdk/commit/26b7000cfec3ccec0530b84df6c030ad51441d98))
* migrate to OAuth 2.0 token endpoint ([ac70a97](https://github.com/semiotic-agentium/agentium-sdk/commit/ac70a97a51efc6977feba9feb4bbbb635e544e5b))
* structured errors in VerificationResult; restore non-throwing verify_jwt ([39aa828](https://github.com/semiotic-agentium/agentium-sdk/commit/39aa828f48283bfa66d5ba3cdafe49f870feb9ae))


### Bug Fixes

* validate JWT has exactly 3 parts ([531067a](https://github.com/semiotic-agentium/agentium-sdk/commit/531067a72fc88661f70ca2bb70193e431ff90d76))

## [0.2.1](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.2.0...agentium-sdk-v0.2.1) (2025-12-04)


### Bug Fixes

* add missing exports ([fe7a56a](https://github.com/semiotic-agentium/agentium-sdk/commit/fe7a56adc8cca3605a467108f2f51083d44e8a70))

## [0.2.0](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-v0.1.0...agentium-sdk-v0.2.0) (2025-12-04)


### Features

* implement initial AgentiumClient class ([092dd48](https://github.com/semiotic-agentium/agentium-sdk/commit/092dd48ef8592106c408de7e25c53bb89abde13d))
* use axios to fetch from identity/connect ([7880bf6](https://github.com/semiotic-agentium/agentium-sdk/commit/7880bf6dc52a705d2903a86abb199a6fddf2c77e))
