<!--
SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.

SPDX-License-Identifier: MIT
-->

# Changelog

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
