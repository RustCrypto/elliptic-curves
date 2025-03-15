# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.14.0 (UNRELEASED)
### Added
- `bits` feature ([#868])
- `elliptic_curve::ops::Invert` implementation ([#971])

## Changed
- Update to `elliptic-curve` v0.14 ([#1011])
- Update to `ecdsa` v0.17 ([#1011])
- Update to `sec1` v0.8 ([#1011])
- Update to `secdect` v0.3 ([#1084])
- Update to `rand_core` v0.9 ([#1125])
- Update to `hybrid-array` v0.3 ([#1125])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#1125])
- Relax MSRV policy and allow MSRV bumps in patch releases

[#868]: https://github.com/RustCrypto/elliptic-curves/pull/868
[#971]: https://github.com/RustCrypto/elliptic-curves/pull/971
[#1011]: https://github.com/RustCrypto/elliptic-curves/pull/1011
[#1084]: https://github.com/RustCrypto/elliptic-curves/pull/1084
[#1125]: https://github.com/RustCrypto/elliptic-curves/pull/1125

## 0.13.0 (2023-04-15)
- Initial release
