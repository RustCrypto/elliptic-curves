# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.2 (2020-10-08)
### Fixed
- Regenerate `rustdoc` on https://docs.rs after nightly breakage

## 0.5.1 (2020-10-08)
### Added
- `SecretValue` impl when `arithmetic` feature is disabled ([#222])

[#222]: https://github.com/RustCrypto/elliptic-curves/pull/222

## 0.5.0 (2020-09-18)
### Added
- `ecdsa::Asn1Signature` type alias ([#186])
- `ff` and `group` crate dependencies; MSRV 1.44+ ([#169], [#174])
- `AffinePoint::identity()` and `::is_identity()` ([#167])

### Changed
- Bump `elliptic-curve` crate to v0.6; `ecdsa` to v0.8 ([#180])
- Refactor ProjectiveArithmetic trait ([#179])
- Support generic inner type for `elliptic_curve::SecretKey<C>` ([#177])
- Rename `ElementBytes` => `FieldBytes` ([#176])
- Rename `ecdsa::{Signer, Verifier}` => `::{SigningKey, VerifyKey}` ([#153])
- Rename `Curve::ElementSize` => `FieldSize` ([#150])
- Implement RFC6979 deterministic ECDSA ([#146], [#147])
- Rename `PublicKey` to `EncodedPoint` ([#141])

### Removed
- `rand` feature ([#162])

[#186]: https://github.com/RustCrypto/elliptic-curves/pull/186
[#180]: https://github.com/RustCrypto/elliptic-curves/pull/180
[#179]: https://github.com/RustCrypto/elliptic-curves/pull/179
[#177]: https://github.com/RustCrypto/elliptic-curves/pull/177
[#176]: https://github.com/RustCrypto/elliptic-curves/pull/176
[#174]: https://github.com/RustCrypto/elliptic-curves/pull/174
[#169]: https://github.com/RustCrypto/elliptic-curves/pull/164
[#167]: https://github.com/RustCrypto/elliptic-curves/pull/167
[#162]: https://github.com/RustCrypto/elliptic-curves/pull/162
[#153]: https://github.com/RustCrypto/elliptic-curves/pull/153
[#150]: https://github.com/RustCrypto/elliptic-curves/pull/150
[#147]: https://github.com/RustCrypto/elliptic-curves/pull/147
[#146]: https://github.com/RustCrypto/elliptic-curves/pull/146
[#141]: https://github.com/RustCrypto/elliptic-curves/pull/141

## 0.4.1 (2020-08-11)
### Fixed
- Builds with either `ecdsa-core` or `sha256` in isolation ([#133])

[#133]: https://github.com/RustCrypto/elliptic-curves/pull/133

## 0.4.0 (2020-08-10)
### Added
- ECDSA support ([#73], [#101], [#104], [#105])
- ECDSA public key recovery support ([#110])
- OID support ([#103], [#113])
- Elliptic Curve Diffie-Hellman ([#120])

### Changed
- Bump `elliptic-curve` crate dependency to v0.5 ([#126])

[#73]: https://github.com/RustCrypto/elliptic-curves/pull/73
[#101]: https://github.com/RustCrypto/elliptic-curves/pull/101
[#103]: https://github.com/RustCrypto/elliptic-curves/pull/103
[#104]: https://github.com/RustCrypto/elliptic-curves/pull/104
[#105]: https://github.com/RustCrypto/elliptic-curves/pull/105
[#110]: https://github.com/RustCrypto/elliptic-curves/pull/110
[#113]: https://github.com/RustCrypto/elliptic-curves/pull/113
[#120]: https://github.com/RustCrypto/elliptic-curves/pull/120
[#126]: https://github.com/RustCrypto/elliptic-curves/pull/126

## 0.3.0 (2020-06-08)
### Changed
- Bump `elliptic-curve` crate dependency to v0.4 ([#39])

[#39]: https://github.com/RustCrypto/elliptic-curves/pull/39

## 0.2.0 (2020-04-30)
### Added
- Constant time scalar multiplication ([#18])
- Group operation ([#15])

[#18]: https://github.com/RustCrypto/elliptic-curves/pull/18
[#15]: https://github.com/RustCrypto/elliptic-curves/pull/15

## 0.1.0 (2020-01-15)
- Initial release
