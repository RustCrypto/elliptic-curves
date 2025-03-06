# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.14.0 (UNRELEASED)
### Added
- hash2curve implementation ([#964])
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

[#964]: https://github.com/RustCrypto/elliptic-curves/pull/964
[#1011]: https://github.com/RustCrypto/elliptic-curves/pull/1011
[#1084]: https://github.com/RustCrypto/elliptic-curves/pull/1084
[#1125]: https://github.com/RustCrypto/elliptic-curves/pull/1125

## 0.13.2 (2023-04-15)
### Changed
- Enable `pem` feature by default ([#832])

### Fixed
- Have `serde` feature enable `primeorder/serde` ([#851])

[#832]: https://github.com/RustCrypto/elliptic-curves/pull/832
[#851]: https://github.com/RustCrypto/elliptic-curves/pull/851

## 0.13.1 (2023-04-10)
### Changed
- Bump `primeorder` to v0.13.1 ([#819])

### Fixed
- Correct product definition for empty iterators ([#802])

[#802]: https://github.com/RustCrypto/elliptic-curves/pull/802
[#819]: https://github.com/RustCrypto/elliptic-curves/pull/819

## 0.13.0 (2023-03-03)
### Added
- `PrimeField` constants/tests ([#730], [#737], [#738])
- `const fn` inversions for all field elements ([#736])

### Changed
- `FieldBytesEncoding` trait impls ([#732])
- Update `hash2curve` implementations to new API ([#735])
- Impl `Invert` trait for `Scalar` types ([#741])
- Bump `ecdsa` dependency to v0.16 ([#770])
- Bump `elliptic-curve` dependency to v0.13 ([#770])
- Bump `primeorder` dependency to v0.13 ([#777])

### Fixed
- Point compactabtility check ([#772])

[#730]: https://github.com/RustCrypto/elliptic-curves/pull/730
[#732]: https://github.com/RustCrypto/elliptic-curves/pull/732
[#735]: https://github.com/RustCrypto/elliptic-curves/pull/735
[#736]: https://github.com/RustCrypto/elliptic-curves/pull/736
[#737]: https://github.com/RustCrypto/elliptic-curves/pull/737
[#738]: https://github.com/RustCrypto/elliptic-curves/pull/738
[#741]: https://github.com/RustCrypto/elliptic-curves/pull/741
[#770]: https://github.com/RustCrypto/elliptic-curves/pull/770
[#772]: https://github.com/RustCrypto/elliptic-curves/pull/772
[#777]: https://github.com/RustCrypto/elliptic-curves/pull/777

## 0.12.0 (2023-01-16)
### Added
- 32-bit scalar backend ([#636])
- `alloc` feature ([#670])
- Constructors for `Scalar` from `u128` ([#709])

### Changed
- Use generic curve arithmetic implementation from `primeorder` crate ([#631], [#716])
- Use `U256` as the inner type for `FieldElement` ([#634])
- Update P-256 VOPRF test vectors ([#693])
- Use weak feature activation; MSRV 1.60 ([#701])
- Bump `ecdsa` dependency to v0.15 ([#713])

[#631]: https://github.com/RustCrypto/elliptic-curves/pull/631
[#634]: https://github.com/RustCrypto/elliptic-curves/pull/634
[#636]: https://github.com/RustCrypto/elliptic-curves/pull/636
[#670]: https://github.com/RustCrypto/elliptic-curves/pull/670
[#693]: https://github.com/RustCrypto/elliptic-curves/pull/693
[#701]: https://github.com/RustCrypto/elliptic-curves/pull/701
[#709]: https://github.com/RustCrypto/elliptic-curves/pull/709
[#713]: https://github.com/RustCrypto/elliptic-curves/pull/713
[#716]: https://github.com/RustCrypto/elliptic-curves/pull/716

## 0.11.1 (2022-06-12)
### Added
- Re-export low-level `diffie_hellman` function ([#556])
- Additional RFC6979 test vectors ([#591])

### Changed
- Use a 4-bit window for scalar multiplication ([#563])
- `invert()`, `sqrt()`: replace exponentiations with addition chains ([#564])
- Use generic prime order formulas ([#602])

[#556]: https://github.com/RustCrypto/elliptic-curves/pull/556
[#563]: https://github.com/RustCrypto/elliptic-curves/pull/563
[#564]: https://github.com/RustCrypto/elliptic-curves/pull/564
[#591]: https://github.com/RustCrypto/elliptic-curves/pull/591
[#602]: https://github.com/RustCrypto/elliptic-curves/pull/602

## 0.11.0 (2022-05-09)
### Changed
- Bump `digest` to v0.10 ([#515])
- Have `pkcs8` feature activate `ecdsa/pkcs8` ([#538])
- Bump `elliptic-curve` to v0.12 ([#544])
- Bump `ecdsa` to v0.14 ([#544])

[#515]: https://github.com/RustCrypto/elliptic-curves/pull/515
[#538]: https://github.com/RustCrypto/elliptic-curves/pull/538
[#544]: https://github.com/RustCrypto/elliptic-curves/pull/544

## 0.10.1 (2022-01-17)
### Added
- Impl `ff::Field` trait for `FieldElement` ([#498])
- hash2curve support: impl `GroupDigest` trait for `NistP256` ([#503])
- Impl `VoprfParameters` trait for `NistP256` ([#506])
- Impl `ReduceNonZero<U256>` trait for `Scalar` ([#507])
- `IDENTITY` and `GENERATOR` point constants ([#509], [#511])

[#498]: https://github.com/RustCrypto/elliptic-curves/pull/498
[#503]: https://github.com/RustCrypto/elliptic-curves/pull/503
[#506]: https://github.com/RustCrypto/elliptic-curves/pull/506
[#507]: https://github.com/RustCrypto/elliptic-curves/pull/507
[#509]: https://github.com/RustCrypto/elliptic-curves/pull/509
[#511]: https://github.com/RustCrypto/elliptic-curves/pull/511

## 0.10.0 (2021-12-14)
### Added
- Implement point compaction support ([#357])
- Implement `Scalar::sqrt` ([#392])
- Impl `DefaultIsZeroes` for `ProjectivePoint` ([#414])
- Impl `PrimeCurveArithmetic` ([#415])
- Impl `Reduce<U256>` for `Scalar` ([#436])
- `serde` feature ([#463], [#465])
- Impl `LinearCombination` trait ([#476])

### Changed
- Use `PrimeCurve` trait ([#413])
- Use `sec1` crate for `EncodedPoint` type ([#435])
- Replace `ecdsa::hazmat::FromDigest` with `Reduce` ([#438])
- Make `FromEncodedPoint` return a `CtOption` ([#445])
- Rust 2021 edition upgrade; MSRV 1.56+ ([#453])
- Leverage generic ECDSA implementation from `ecdsa` crate ([#462])
- Bump `elliptic-curve` crate dependency to v0.11 ([#466])
- Bump `ecdsa` crate dependency to v0.13 ([#467])

### Fixed
- `ProjectivePoint::to_bytes()` encoding for identity ([#443])
- Handle identity point in `GroupEncoding` ([#446])

[#357]: https://github.com/RustCrypto/elliptic-curves/pull/357
[#392]: https://github.com/RustCrypto/elliptic-curves/pull/392
[#413]: https://github.com/RustCrypto/elliptic-curves/pull/413
[#414]: https://github.com/RustCrypto/elliptic-curves/pull/414
[#415]: https://github.com/RustCrypto/elliptic-curves/pull/415
[#435]: https://github.com/RustCrypto/elliptic-curves/pull/435
[#436]: https://github.com/RustCrypto/elliptic-curves/pull/436
[#438]: https://github.com/RustCrypto/elliptic-curves/pull/438
[#443]: https://github.com/RustCrypto/elliptic-curves/pull/443
[#445]: https://github.com/RustCrypto/elliptic-curves/pull/445
[#446]: https://github.com/RustCrypto/elliptic-curves/pull/446
[#453]: https://github.com/RustCrypto/elliptic-curves/pull/453
[#463]: https://github.com/RustCrypto/elliptic-curves/pull/463
[#465]: https://github.com/RustCrypto/elliptic-curves/pull/465
[#466]: https://github.com/RustCrypto/elliptic-curves/pull/466
[#467]: https://github.com/RustCrypto/elliptic-curves/pull/467
[#476]: https://github.com/RustCrypto/elliptic-curves/pull/476

## 0.9.0 (2021-06-08)
### Added
- `AffineArithmetic` trait impl ([#347])
- `PrimeCurve` trait impls ([#350])

### Changed
- Bump `elliptic-curve` to v0.10; MSRV 1.51+ ([#349])
- Bump `ecdsa` to v0.12 ([#349])

[#347]: https://github.com/RustCrypto/elliptic-curves/pull/347
[#349]: https://github.com/RustCrypto/elliptic-curves/pull/349
[#350]: https://github.com/RustCrypto/elliptic-curves/pull/350

## 0.8.1 (2021-05-10)
### Fixed
- Mixed coordinate addition with the point at infinity ([#337])

[#337]: https://github.com/RustCrypto/elliptic-curves/pull/337

## 0.8.0 (2021-04-29)
### Added
- `jwk` feature ([#279])
- Wycheproof ECDSA P-256 test vectors ([#313])
- `Order` constant ([#328])

### Changed
- Rename `ecdsa::Asn1Signature` to `::DerSignature` ([#288])
- Migrate to `FromDigest` trait from `ecdsa` crate ([#292])
- Bump `elliptic-curve` to v0.9.2 ([#296])
- Bump `pkcs8` to v0.6 ([#319])
- Bump `ecdsa` crate dependency to v0.11 ([#330])

### Fixed
- `DigestPrimitive` feature gating ([#324])

[#279]: https://github.com/RustCrypto/elliptic-curves/pull/279
[#288]: https://github.com/RustCrypto/elliptic-curves/pull/288
[#292]: https://github.com/RustCrypto/elliptic-curves/pull/292
[#296]: https://github.com/RustCrypto/elliptic-curves/pull/296
[#313]: https://github.com/RustCrypto/elliptic-curves/pull/313
[#319]: https://github.com/RustCrypto/elliptic-curves/pull/319
[#324]: https://github.com/RustCrypto/elliptic-curves/pull/324
[#328]: https://github.com/RustCrypto/elliptic-curves/pull/328
[#330]: https://github.com/RustCrypto/elliptic-curves/pull/330

## 0.7.3 (2021-04-16)
### Changed
- Make `ecdsa` a default feature ([#325])

[#325]: https://github.com/RustCrypto/elliptic-curves/pull/325

## 0.7.2 (2021-01-13)
### Changed
- Have `std` feature activate `ecdsa-core/std` ([#273])

[#273]: https://github.com/RustCrypto/elliptic-curves/pull/273

## 0.7.1 (2020-12-16)
### Fixed
- Trigger docs.rs rebuild with nightly bugfix ([RustCrypto/traits#412])

[RustCrypto/traits#412]: https://github.com/RustCrypto/traits/pull/412

## 0.7.0 (2020-12-16)
### Changed
- Bump `elliptic-curve` dependency to v0.8 ([#260])
- Bump `ecdsa` to v0.10 ([#260])

[#260]: https://github.com/RustCrypto/elliptic-curves/pull/260

## 0.6.0 (2020-12-06)
### Added
- PKCS#8 support ([#243], [#244], [#245])
- `PublicKey` type ([#239])

### Changed
- Bump `elliptic-curve` crate dependency to v0.7; MSRV 1.46+ ([#247])
- Bump `ecdsa` crate dependency to v0.9 ([#247])

[#247]: https://github.com/RustCrypto/elliptic-curves/pull/247
[#245]: https://github.com/RustCrypto/elliptic-curves/pull/245
[#244]: https://github.com/RustCrypto/elliptic-curves/pull/244
[#243]: https://github.com/RustCrypto/elliptic-curves/pull/243
[#239]: https://github.com/RustCrypto/elliptic-curves/pull/239

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
