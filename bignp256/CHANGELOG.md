# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.14.0 (UNRELEASED)
### Added
- ECDH and PKCS8 support ([#1046])
- `bits`, `serde`, and `test-vectors` features ([#1062])

## Changed
- Update to `digest` v0.11 ([#1011])
- Update to `pkcs8` v0.11 ([#1011])
- Update to `sec1` v0.8 ([#1011])
- Update to `rand_core` v0.9 ([#1125])
- Update to `hybrid-array` v0.3 ([#1125])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#1125])
- Relax MSRV policy and allow MSRV bumps in patch releases

[#1011]: https://github.com/RustCrypto/elliptic-curves/pull/1011
[#1046]: https://github.com/RustCrypto/elliptic-curves/pull/1046
[#1062]: https://github.com/RustCrypto/elliptic-curves/pull/1062
[#1125]: https://github.com/RustCrypto/elliptic-curves/pull/1125

## 0.13.1 (2024-01-05)
### Added
- Digital signature algorithm ([#935])

[#935]: https://github.com/RustCrypto/elliptic-curves/pull/935

## 0.13.0 (2023-06-27)
- Initial release
