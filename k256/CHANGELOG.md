# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.1 (2020-08-10)
### Fixed
- secp256k1 rustdoc link ([#131])

[#131]: https://github.com/RustCrypto/elliptic-curves/pull/131

## 0.4.0 (2020-08-10)
### Added
- ECDSA support ([#73], [#101], [#104], [#105])
- ECDSA public key recovery support ([#110])
- OID support ([#103], [#113])
- Elliptic Curve Diffie-Hellman ([#120])
- `Zeroize` impl for `AffinePoint` and `FieldElement` types ([#124])

### Changed
- Optimized field arithmetic with 32-bit and 64-bit backends ([#59], [#82])
- Bump `elliptic-curve` crate dependency to v0.5 ([#126])

[#59]: https://github.com/RustCrypto/elliptic-curves/pull/59
[#73]: https://github.com/RustCrypto/elliptic-curves/pull/73
[#82]: https://github.com/RustCrypto/elliptic-curves/pull/82
[#101]: https://github.com/RustCrypto/elliptic-curves/pull/101
[#103]: https://github.com/RustCrypto/elliptic-curves/pull/103
[#104]: https://github.com/RustCrypto/elliptic-curves/pull/104
[#105]: https://github.com/RustCrypto/elliptic-curves/pull/105
[#110]: https://github.com/RustCrypto/elliptic-curves/pull/110
[#113]: https://github.com/RustCrypto/elliptic-curves/pull/113
[#120]: https://github.com/RustCrypto/elliptic-curves/pull/120
[#124]: https://github.com/RustCrypto/elliptic-curves/pull/124
[#126]: https://github.com/RustCrypto/elliptic-curves/pull/126

## 0.3.0 (2020-06-08)
### Changed
- Bump `elliptic-curve` crate dependency to v0.4 ([#39])

[#39]: https://github.com/RustCrypto/elliptic-curves/pull/39

## 0.2.0 (2020-04-30)
### Added
- Field arithmetic, point addition/doubling, and scalar multiplication ([#19])

[#19]: https://github.com/RustCrypto/elliptic-curves/pull/19

## 0.1.1 (2020-04-20)
### Fixed
- README.md: fix typo in crate name ([#16])

[#16]: https://github.com/RustCrypto/elliptic-curves/pull/16

## 0.1.0 (2020-01-15)
- Initial release
