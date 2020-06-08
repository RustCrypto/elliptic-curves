# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0 (2020-06-04)
### Changed
- Bump `generic-array` dependency from v0.12 to v0.14 ([#38])

[#38]: https://github.com/RustCrypto/elliptic-curves/pull/38

## 0.3.0 (2020-01-15)
### Added
- `Scalar` struct type ([#5])

### Changed
- Repository moved to <https://github.com/RustCrypto/elliptic-curves>

### Removed
- Curve definitions/arithmetic extracted out into per-curve crates ([#5])

[#5]: https://github.com/RustCrypto/elliptic-curves/pull/5

## 0.2.0 (2019-12-11)
### Added
- `secp256r1` (P-256) point compression and decompression ([RustCrypto/signatures#63], [RustCrypto/signatures#64])

### Changed
- Bump MSRV to 1.37 ([RustCrypto/signatures#63])

[RustCrypto/signatures#63]: https://github.com/RustCrypto/signatures/pull/63
[RustCrypto/signatures#64]: https://github.com/RustCrypto/signatures/pull/64

## 0.1.0 (2019-12-06)
- Initial release
