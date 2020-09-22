# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.2 (2020-09-22)
### Fixed
- Corrected imports when using `ecdsa` + `keccak256` features ([#199])

[#199]: https://github.com/RustCrypto/elliptic-curves/pull/199

## 0.5.1 (2020-09-21)
### Added
- Documentation for `sha256` feature ([#197])
- `sec1::EncodedPoint::decompress` test ([#194])
- Impl `RandomizedSigner` on `SigningKey` ([#193])

### Changed
- Gate ecdsa::{Signer, Verifier} impls on `sha256` feature ([#192])

[#197]: https://github.com/RustCrypto/elliptic-curves/pull/197
[#194]: https://github.com/RustCrypto/elliptic-curves/pull/194
[#193]: https://github.com/RustCrypto/elliptic-curves/pull/193
[#192]: https://github.com/RustCrypto/elliptic-curves/pull/192

## 0.5.0 (2020-09-17)
### Added
- `ecdsa::Asn1Signature` type alias ([#186])
- `ff` and `group` crate dependencies; MSRV 1.44+ ([#164], [#174])
- `AffinePoint::identity()` and `::is_identity()` ([#165])
- `expose-field` feature ([#161])
- `keccak256` feature ([#142])

### Changed
- Bump `elliptic-curve` crate to v0.6; `ecdsa` to v0.8 ([#180])
- Refactor ProjectiveArithmetic trait ([#179])
- Support generic inner type for `elliptic_curve::SecretKey<C>` ([#177])
- Rename `ElementBytes` => `FieldBytes` ([#176])
- Factor out a `from_digest_trial_recovery` method ([#168])
- Rename `ecdsa::{Signer, Verifier}` => `::{SigningKey, VerifyKey}` ([#153])
- Rename `Curve::ElementSize` => `FieldSize` ([#150])
- Implement RFC6979 deterministic ECDSA ([#146])
- Use `NonZeroScalar` for ECDSA signature components ([#144])
- Eagerly verify ECDSA scalars are in range ([#143])
- Rename `PublicKey` to `EncodedPoint` ([#141])

### Removed
- `rand` feature ([#162])

[#186]: https://github.com/RustCrypto/elliptic-curves/pull/186
[#180]: https://github.com/RustCrypto/elliptic-curves/pull/180
[#179]: https://github.com/RustCrypto/elliptic-curves/pull/179
[#177]: https://github.com/RustCrypto/elliptic-curves/pull/177
[#176]: https://github.com/RustCrypto/elliptic-curves/pull/176
[#174]: https://github.com/RustCrypto/elliptic-curves/pull/174
[#168]: https://github.com/RustCrypto/elliptic-curves/pull/168
[#165]: https://github.com/RustCrypto/elliptic-curves/pull/165
[#164]: https://github.com/RustCrypto/elliptic-curves/pull/164
[#162]: https://github.com/RustCrypto/elliptic-curves/pull/162
[#161]: https://github.com/RustCrypto/elliptic-curves/pull/161
[#153]: https://github.com/RustCrypto/elliptic-curves/pull/153
[#150]: https://github.com/RustCrypto/elliptic-curves/pull/150
[#146]: https://github.com/RustCrypto/elliptic-curves/pull/146
[#144]: https://github.com/RustCrypto/elliptic-curves/pull/144
[#143]: https://github.com/RustCrypto/elliptic-curves/pull/143
[#142]: https://github.com/RustCrypto/elliptic-curves/pull/142
[#141]: https://github.com/RustCrypto/elliptic-curves/pull/141

## 0.4.2 (2020-08-11)
### Fixed
- Builds with either `ecdsa-core` or `sha256` in isolation ([#133])

[#133]: https://github.com/RustCrypto/elliptic-curves/pull/133

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
