# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.14.0 (2026-10-02)
### Added
- SM2PKE encryption support via the `pke` feature ([#1069])
- SM2DSA signature algorithm support via the `dsa` feature ([#1127])
- Implement `From<NonZeroScalar>` for `Scalar` ([#1188])
- Implement `MultipartSigner`, `RandomizedMultipartSigner`, and `MultipartVerifier` ([#1221])
- Implement `crypto_common::Generate` trait ([#1586])
- `cfg(sm2_backend)` with `bigint` and `fiat` options ([#1596], [#1806])
- `UncompressedPoint` type alias ([#1604])
- `precomputed-tables` feature ([#1740], [#1793])

### Changed
- Edition changed to 2024 and MSRV bumped to 1.85 ([#1125])
- Relax MSRV policy and allow MSRV bumps in patch releases ([#1125])
- `sm2_backend="fiat"` now uses `fiat-crypto` crate ([#1431])
- `getrandom` feature now enabled by default ([#1521])
- Bump `sm3` dependency to v0.5 ([#1699])
- Bump `signature` dependency to v3 ([#1756])
- Bump `elliptic-curve` to v0.14 ([#1849])
- Bump `primeorder` v0.14 ([#1887])

[#1069]: https://github.com/RustCrypto/elliptic-curves/pull/1069
[#1125]: https://github.com/RustCrypto/elliptic-curves/pull/1125
[#1127]: https://github.com/RustCrypto/elliptic-curves/pull/1127
[#1188]: https://github.com/RustCrypto/elliptic-curves/pull/1188
[#1221]: https://github.com/RustCrypto/elliptic-curves/pull/1221
[#1431]: https://github.com/RustCrypto/elliptic-curves/pull/1431
[#1521]: https://github.com/RustCrypto/elliptic-curves/pull/1521
[#1586]: https://github.com/RustCrypto/elliptic-curves/pull/1586
[#1596]: https://github.com/RustCrypto/elliptic-curves/pull/1596
[#1604]: https://github.com/RustCrypto/elliptic-curves/pull/1604
[#1699]: https://github.com/RustCrypto/elliptic-curves/pull/1699
[#1740]: https://github.com/RustCrypto/elliptic-curves/pull/1740
[#1756]: https://github.com/RustCrypto/elliptic-curves/pull/1756
[#1793]: https://github.com/RustCrypto/elliptic-curves/pull/1793
[#1806]: https://github.com/RustCrypto/elliptic-curves/pull/1806
[#1849]: https://github.com/RustCrypto/elliptic-curves/pull/1849
[#1887]: https://github.com/RustCrypto/elliptic-curves/pull/1887

## 0.13.3 (2023-11-20)
### Added
- Impl `Randomized*Signer` for `sm2::dsa::SigningKey` ([#993])

[#993]: https://github.com/RustCrypto/elliptic-curves/pull/993

## 0.13.2 (2023-04-15)
### Changed
- Factor out `distid` module ([#865])

[#865]: https://github.com/RustCrypto/elliptic-curves/pull/865

## 0.13.1 (2023-04-15) [YANKED]
### Added
- Enable `dsa` feature by default ([#862])

[#862]: https://github.com/RustCrypto/elliptic-curves/pull/862

## 0.13.0 (2023-04-15) [YANKED]
- Initial RustCrypto release

## 0.0.1 (2020-03-02)
