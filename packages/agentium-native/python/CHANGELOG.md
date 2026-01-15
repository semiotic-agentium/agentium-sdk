# Changelog


## [0.5.0](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-python-v0.4.8...agentium-sdk-python-v0.5.0) (2026-01-15)


### ⚠ BREAKING CHANGES

* **python:** `connect_wallet` argument order changed from (address, chain_id, private_key) to (address, private_key, chain_id).

### Features

* **python:** add Caip2 type support and default chain for wallet auth ([54c75f0](https://github.com/semiotic-agentium/agentium-sdk/commit/54c75f003fd357d77e8875af1370ded3b79d16c3))


### Bug Fixes

* **python:** add constant to Caip class definition ([ee2a097](https://github.com/semiotic-agentium/agentium-sdk/commit/ee2a0970de8f56d18f2a8cfcd975558669be514f))


### Documentation

* Add documentation about supported/unsupported platforms ([0c18fae](https://github.com/semiotic-agentium/agentium-sdk/commit/0c18faee3b73e7e4d738d3a0a92865c701a9fc15))

## [0.4.8](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-python-v0.4.7...agentium-sdk-python-v0.4.8) (2026-01-15)


### Bug Fixes

* **python:** install zig on container used for aarch64 wheels ([fde53d4](https://github.com/semiotic-agentium/agentium-sdk/commit/fde53d49c3141d5d3522d71145b8edd15fe5df8f))

## [0.4.7](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-python-v0.4.6...agentium-sdk-python-v0.4.7) (2026-01-15)


### Bug Fixes

* **python:** set CC flag to use zig for aarch64 builds ([94d6e01](https://github.com/semiotic-agentium/agentium-sdk/commit/94d6e016f7e6c7808947c1ea33a7c9689c38d0d6))

## [0.4.6](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-python-v0.4.5...agentium-sdk-python-v0.4.6) (2026-01-15)


### Bug Fixes

* **python:** disable sccache for aarh64 builds ([ff33045](https://github.com/semiotic-agentium/agentium-sdk/commit/ff33045ccdc407446b9e80311c57516d2c0a2eae))

## [0.4.5](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-python-v0.4.4...agentium-sdk-python-v0.4.5) (2026-01-14)


### Bug Fixes

* **python:** set python version ([3007a58](https://github.com/semiotic-agentium/agentium-sdk/commit/3007a588dd1ff29472cb6b38b45248d9a1051f5b))

## [0.4.4](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-python-v0.4.3...agentium-sdk-python-v0.4.4) (2026-01-14)


### Bug Fixes

* **python:** fix cross-compilation issue for aarch64 targets ([2246d02](https://github.com/semiotic-agentium/agentium-sdk/commit/2246d02ac15148d6230e7d0b79e0a2ee93da1985))

## [0.4.3](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-python-v0.4.2...agentium-sdk-python-v0.4.3) (2026-01-14)


### Bug Fixes

* **python:** trigger release to test wheel build fixes ([7c571f1](https://github.com/semiotic-agentium/agentium-sdk/commit/7c571f136a09febb3c673acff03c9372bc60be28))

## [0.4.2](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-python-v0.4.1...agentium-sdk-python-v0.4.2) (2026-01-14)


### Bug Fixes

* **python:** trigger release to test wheel build fixes ([100cefc](https://github.com/semiotic-agentium/agentium-sdk/commit/100cefc6aaf6a62a912e3c71b3813d8bb64e050b))
* **python:** trigger release to test wheel build fixes ([e6110f8](https://github.com/semiotic-agentium/agentium-sdk/commit/e6110f833c1f0bf4298d673e8125205f8c714669))

## [0.4.1](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-python-v0.4.0...agentium-sdk-python-v0.4.1) (2026-01-14)


### Bug Fixes

* **python:** trigger release with corrected wheel build configuration ([c80f5f3](https://github.com/semiotic-agentium/agentium-sdk/commit/c80f5f3c3b4f96dc0ae1231884131d55867e8e25))

## [0.4.0](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-python-v0.3.0...agentium-sdk-python-v0.4.0) (2026-01-14)


### Features

* add PyO3 native bindings for agentium-sdk ([71cf961](https://github.com/semiotic-agentium/agentium-sdk/commit/71cf9616a2ebe44aaeb14d47c52177a2e4f66941))
* add Python SDK interface for Agentium Network ([fbf83b2](https://github.com/semiotic-agentium/agentium-sdk/commit/fbf83b2f802eec36b2cfa739ba554f70a6be7eee))
* **python:** expose wallet authentication bindings ([6e53d84](https://github.com/semiotic-agentium/agentium-sdk/commit/6e53d84935690d0a700b5310ee77a383403bfb22))
* return claims as native Python dict via pythonize ([ea8624f](https://github.com/semiotic-agentium/agentium-sdk/commit/ea8624faca6558b4024815aeb0175d979a3322f5))
* SDK improvements and rename to agentium-sdk ([9c55a7f](https://github.com/semiotic-agentium/agentium-sdk/commit/9c55a7fab355d236e41fd942477ef0f57b2f0531))
* **sdk:** add wallet sign-in authentication methods ([04122c4](https://github.com/semiotic-agentium/agentium-sdk/commit/04122c48ba092247c9651e5462d1dd65fb71e084))


### Bug Fixes

* **python:** resolve mypy type errors ([aec6ca7](https://github.com/semiotic-agentium/agentium-sdk/commit/aec6ca78070e20952b00193f8b06a3d5ad15e627))
* use distinct tag prefix for Python releases ([38a60f6](https://github.com/semiotic-agentium/agentium-sdk/commit/38a60f6b6abda13fae9bd32a50f792204e90af9b))


### Documentation

* add missing declaration for init_tracing function ([f348181](https://github.com/semiotic-agentium/agentium-sdk/commit/f34818130a65bbf318dac9cfa9bc24ce88b33eac))
* add new wallet sign-in documentation ([a018766](https://github.com/semiotic-agentium/agentium-sdk/commit/a0187662635f3ddf4e80b507d1923a82a650b3d4))
* add python docs dir ([4208239](https://github.com/semiotic-agentium/agentium-sdk/commit/4208239c526bbf1ea556fffb2a381211263a622d))
* add Python SDK documentation and GitHub Pages workflow ([d156a38](https://github.com/semiotic-agentium/agentium-sdk/commit/d156a38ca82b019163267c9d75bd5538a3d290f5))
* improve python sdk README ([aa7d6d5](https://github.com/semiotic-agentium/agentium-sdk/commit/aa7d6d5866b7e6d668b4810008279e67d79cc1c9))
* **python:** improve SDK documentation and getting started guide ([7a9a7ee](https://github.com/semiotic-agentium/agentium-sdk/commit/7a9a7eea5bff26cfb36e31e8a3b5abe9eaec4321))
* update documentation regarding claims change ([fe30da8](https://github.com/semiotic-agentium/agentium-sdk/commit/fe30da8306912ec25565a7e6bb7ca4841f65f85d))

## [0.2.0](https://github.com/semiotic-agentium/agentium-sdk/compare/agentium-sdk-python-v0.1.0...agentium-sdk-python-v0.2.0) (2026-01-14)


### Features

* add PyO3 native bindings for agentium-sdk ([71cf961](https://github.com/semiotic-agentium/agentium-sdk/commit/71cf9616a2ebe44aaeb14d47c52177a2e4f66941))
* add Python SDK interface for Agentium Network ([fbf83b2](https://github.com/semiotic-agentium/agentium-sdk/commit/fbf83b2f802eec36b2cfa739ba554f70a6be7eee))
* **python:** expose wallet authentication bindings ([6e53d84](https://github.com/semiotic-agentium/agentium-sdk/commit/6e53d84935690d0a700b5310ee77a383403bfb22))
* return claims as native Python dict via pythonize ([ea8624f](https://github.com/semiotic-agentium/agentium-sdk/commit/ea8624faca6558b4024815aeb0175d979a3322f5))
* SDK improvements and rename to agentium-sdk ([9c55a7f](https://github.com/semiotic-agentium/agentium-sdk/commit/9c55a7fab355d236e41fd942477ef0f57b2f0531))
* **sdk:** add wallet sign-in authentication methods ([04122c4](https://github.com/semiotic-agentium/agentium-sdk/commit/04122c48ba092247c9651e5462d1dd65fb71e084))


### Bug Fixes

* **python:** resolve mypy type errors ([aec6ca7](https://github.com/semiotic-agentium/agentium-sdk/commit/aec6ca78070e20952b00193f8b06a3d5ad15e627))


### Documentation

* add missing declaration for init_tracing function ([f348181](https://github.com/semiotic-agentium/agentium-sdk/commit/f34818130a65bbf318dac9cfa9bc24ce88b33eac))
* add new wallet sign-in documentation ([a018766](https://github.com/semiotic-agentium/agentium-sdk/commit/a0187662635f3ddf4e80b507d1923a82a650b3d4))
* add python docs dir ([4208239](https://github.com/semiotic-agentium/agentium-sdk/commit/4208239c526bbf1ea556fffb2a381211263a622d))
* add Python SDK documentation and GitHub Pages workflow ([d156a38](https://github.com/semiotic-agentium/agentium-sdk/commit/d156a38ca82b019163267c9d75bd5538a3d290f5))
* improve python sdk README ([aa7d6d5](https://github.com/semiotic-agentium/agentium-sdk/commit/aa7d6d5866b7e6d668b4810008279e67d79cc1c9))
* **python:** improve SDK documentation and getting started guide ([7a9a7ee](https://github.com/semiotic-agentium/agentium-sdk/commit/7a9a7eea5bff26cfb36e31e8a3b5abe9eaec4321))
* update documentation regarding claims change ([fe30da8](https://github.com/semiotic-agentium/agentium-sdk/commit/fe30da8306912ec25565a7e6bb7ca4841f65f85d))
