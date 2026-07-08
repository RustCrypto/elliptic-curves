# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.14.0 (2026-07-08)
### Added
- Implement `EcdsaCurve` ([#1019])
- Implement `ReduceNonZero` for `Scalar` ([#1148])
- Implement `From<NonZeroScalar>` for `Scalar` ([#1188])
- Implement `De/Serialize` for `ProjectivePoint` ([#1214])
- `hash2curve` crate support ([#1286], [#1853])
- Implement `CofactorGroup` for `ProjectivePoint` ([#1394])
- 32-bit base field implementation; `Uint` type as conditional alias for `U544`/`U576` ([#1467])
- `getrandom` feature ([#1521])
- Implement `crypto_common::Generate` trait ([#1586])
- `precomputed-tables` feature ([#1738], [#1792])
- Implement `FieldArithmetic` trait ([#1833])

### Changed
- ECDSA implementation now uses RFC6979 by way of the `ecdsa`/`rfc6979` crates ([#1016])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#1125])
- Relax MSRV policy and allow MSRV bumps in patch releases
- Base field implementation regenerated using `fiat-crypto` v0.1.5 ([#1413])
- `NistP521::Uint` is now the `Uint` type alias instead of unconditionally `U576` ([#1467])
- Use `primefield::MontyFieldElement` for `Scalar` field arithmetic ([#1565])
- Use `crypto-bigint` to implement field inversions ([#1574])
- Bump `sha2` dependency to v0.11 ([#1712])
- Bump `elliptic-curve` to v0.14 ([#1849])
- Use `wnaf` for vartime (multi)scalar multiplication ([#1870])
- Bump `ecdsa` to v0.17 ([#1883])
- Bump `primeorder` to v0.14 ([#1887])

### Removed
- `bits` feature ([#1766])
- `expose-field` feature: use `FieldArithmetic` trait instead ([#1834])

### Fixed
- Size of `CompressedPoint` ([#1652])

[#1016]: https://github.com/RustCrypto/elliptic-curves/pull/1016
[#1019]: https://github.com/RustCrypto/elliptic-curves/pull/1019
[#1125]: https://github.com/RustCrypto/elliptic-curves/pull/1125
[#1148]: https://github.com/RustCrypto/elliptic-curves/pull/1148
[#1188]: https://github.com/RustCrypto/elliptic-curves/pull/1188
[#1214]: https://github.com/RustCrypto/elliptic-curves/pull/1214
[#1286]: https://github.com/RustCrypto/elliptic-curves/pull/1286
[#1394]: https://github.com/RustCrypto/elliptic-curves/pull/1394
[#1413]: https://github.com/RustCrypto/elliptic-curves/pull/1413
[#1467]: https://github.com/RustCrypto/elliptic-curves/pull/1467
[#1521]: https://github.com/RustCrypto/elliptic-curves/pull/1521
[#1565]: https://github.com/RustCrypto/elliptic-curves/pull/1565
[#1574]: https://github.com/RustCrypto/elliptic-curves/pull/1574
[#1586]: https://github.com/RustCrypto/elliptic-curves/pull/1586
[#1652]: https://github.com/RustCrypto/elliptic-curves/pull/1652
[#1712]: https://github.com/RustCrypto/elliptic-curves/pull/1712
[#1738]: https://github.com/RustCrypto/elliptic-curves/pull/1738
[#1766]: https://github.com/RustCrypto/elliptic-curves/pull/1766
[#1792]: https://github.com/RustCrypto/elliptic-curves/pull/1792
[#1833]: https://github.com/RustCrypto/elliptic-curves/pull/1833
[#1834]: https://github.com/RustCrypto/elliptic-curves/pull/1834
[#1849]: https://github.com/RustCrypto/elliptic-curves/pull/1849
[#1853]: https://github.com/RustCrypto/elliptic-curves/pull/1853
[#1870]: https://github.com/RustCrypto/elliptic-curves/pull/1870
[#1883]: https://github.com/RustCrypto/elliptic-curves/pull/1883
[#1887]: https://github.com/RustCrypto/elliptic-curves/pull/1887

## 0.13.3 (2023-11-11)
### Added
- Implement hash2curve ([#964])

### Fixed
- Panics when decoding `FieldElement`s ([#967])

[#964]: https://github.com/RustCrypto/elliptic-curves/pull/964
[#967]: https://github.com/RustCrypto/elliptic-curves/pull/967

## 0.13.2 (2023-11-09)
### Added
- `serde` feature ([#962])

### Changed
- Remove `pub` from `arithmetic` module ([#961])

[#961]: https://github.com/RustCrypto/elliptic-curves/pull/961
[#962]: https://github.com/RustCrypto/elliptic-curves/pull/962

## 0.13.1 (2023-11-09) [YANKED]
### Added
- Bernstein-Yang scalar inversions ([#786])
- VOPRF support ([#924])
- `arithmetic` feature ([#953])
- `ecdh` feature ([#954])
- `ecdsa` feature ([#956])

[#786]: https://github.com/RustCrypto/elliptic-curves/pull/786
[#924]: https://github.com/RustCrypto/elliptic-curves/pull/924
[#953]: https://github.com/RustCrypto/elliptic-curves/pull/953
[#954]: https://github.com/RustCrypto/elliptic-curves/pull/954
[#956]: https://github.com/RustCrypto/elliptic-curves/pull/956

## 0.13.0 (2023-03-03) [YANKED]
- Initial release
