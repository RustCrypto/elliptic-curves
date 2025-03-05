# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.14.0 (UNRELEASED)
### Added
- `bits` feature ([#868])
- `Scalar::sqrt` implementation ([#904])
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
[#904]: https://github.com/RustCrypto/elliptic-curves/pull/904
[#971]: https://github.com/RustCrypto/elliptic-curves/pull/971
[#1011]: https://github.com/RustCrypto/elliptic-curves/pull/1011
[#1084]: https://github.com/RustCrypto/elliptic-curves/pull/1084
[#1125]: https://github.com/RustCrypto/elliptic-curves/pull/1125

## 0.13.2 (2023-04-15)
### Changed
- Enable `arithmetic` and `ecdsa` by default ([#833])

### Fixed
- Have `serde` feature enable `primeorder/serde` ([#851])

[#833]: https://github.com/RustCrypto/elliptic-curves/pull/833
[#851]: https://github.com/RustCrypto/elliptic-curves/pull/851

## 0.13.1 (2023-04-09)
### Added
- Projective arithmetic tests ([#813])
- `ecdh` feature ([#814])
- `arithmetic` feature ([#815])
- `ecdsa` feature ([#816])
- FIPS 186-4 ECDSA test vectors ([#817])
- Wycheproof test vectors ([#818])
- Bump `primeorder` to v0.13.1 ([#819])

### Changed
- Better `Debug` for field elements ([#798])
- Make `primeorder` dependency optional ([#799])

[#798]: https://github.com/RustCrypto/elliptic-curves/pull/798
[#799]: https://github.com/RustCrypto/elliptic-curves/pull/799
[#813]: https://github.com/RustCrypto/elliptic-curves/pull/813
[#814]: https://github.com/RustCrypto/elliptic-curves/pull/814
[#815]: https://github.com/RustCrypto/elliptic-curves/pull/815
[#816]: https://github.com/RustCrypto/elliptic-curves/pull/816
[#817]: https://github.com/RustCrypto/elliptic-curves/pull/817
[#818]: https://github.com/RustCrypto/elliptic-curves/pull/818
[#819]: https://github.com/RustCrypto/elliptic-curves/pull/819

## 0.13.0 (2023-03-03)
- Initial release
