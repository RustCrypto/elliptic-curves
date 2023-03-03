# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.13.0 (2023-03-03)
### Added
- Support curves with any `a`-coefficient ([#728], [#729])
- `impl_primefield_tests!` macro ([#739])

### Changed
- Use `AffineCoordinates` trait ([#734])
- Rename `impl_field_element!` to `impl_mont_field_element!` ([#762])
- Bump `elliptic-curve` dependency to v0.13 ([#770])
- Bump `ecdsa` to v0.16 ([#770])

[#728]: https://github.com/RustCrypto/elliptic-curves/pull/728
[#729]: https://github.com/RustCrypto/elliptic-curves/pull/729
[#734]: https://github.com/RustCrypto/elliptic-curves/pull/734
[#739]: https://github.com/RustCrypto/elliptic-curves/pull/739
[#762]: https://github.com/RustCrypto/elliptic-curves/pull/762
[#770]: https://github.com/RustCrypto/elliptic-curves/pull/770

## 0.12.1 (2023-01-22)
### Added
- Impl `From/ToEncodedPoint` for `ProjectivePoint` ([#722])

[#722]: https://github.com/RustCrypto/elliptic-curves/pull/722

## 0.12.0 (2023-01-16)

Initial stable release.

NOTE: other versions skipped to synchronize version numbers with
`elliptic-curve`, `k256`, `p256`, and `p384`.

## 0.0.2 (2022-12-29)

## 0.0.1 (2022-11-06)
