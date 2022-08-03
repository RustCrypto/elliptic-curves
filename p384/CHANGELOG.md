# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.11.2 (2022-08-03)
### Added
- Re-export low-level `diffie_hellman` function ([#627])

[#627]: https://github.com/RustCrypto/elliptic-curves/pull/627

## 0.11.1 (2022-06-12)
### Added
- RFC6979 test vectors ([#591])
- Impl `serde::{Serialize, Deserialize}` for `Scalar` ([#604])

### Changed
- Use generic prime order formulas ([#601])

[#591]: https://github.com/RustCrypto/elliptic-curves/pull/591
[#601]: https://github.com/RustCrypto/elliptic-curves/pull/601
[#604]: https://github.com/RustCrypto/elliptic-curves/pull/604

## 0.11.0 (2022-06-03)
### Added
- Arithmetic implementation ([#565], [#573])
  - Addition formulas from Renes-Costello-Batina 2015, adapted from
    @str4d's implementation in the `p256` crate
  - `FieldElement::{invert, sqrt}` implementations
  - `Scalar::{invert, sqrt}` implementations
  - Scalar field implementation generated using `fiat-crypto`
  - Scalar multiplication using 4-bit window ala [#563]
  - ECDH support using generic implementation from `elliptic-curve`
  - ECDSA support using generic implementation from the `ecdsa` crate
- Wycheproof test vectors ([#574])
- `const fn` field arithmetic ([#589], [#590])

[#563]: https://github.com/RustCrypto/elliptic-curves/pull/563
[#565]: https://github.com/RustCrypto/elliptic-curves/pull/565
[#573]: https://github.com/RustCrypto/elliptic-curves/pull/573
[#574]: https://github.com/RustCrypto/elliptic-curves/pull/574
[#589]: https://github.com/RustCrypto/elliptic-curves/pull/589
[#590]: https://github.com/RustCrypto/elliptic-curves/pull/590

## 0.10.0 (2022-05-09)
### Changed
- Bump `digest` to v0.10 ([#515])
- Have `pkcs8` feature activate `ecdsa/pkcs8` ([#538])
- Bump `elliptic-curve` to v0.12 ([#544])
- Bump `ecdsa` to v0.14 ([#544])

[#515]: https://github.com/RustCrypto/elliptic-curves/pull/515
[#538]: https://github.com/RustCrypto/elliptic-curves/pull/538
[#544]: https://github.com/RustCrypto/elliptic-curves/pull/544

## 0.9.0 (2021-12-14)
### Added
- `serde` feature ([#463])

### Changed
- Use `sec1` crate for `EncodedPoint` type ([#435])
- Rust 2021 edition upgrade; MSRV 1.56+ ([#453])
- Bump `elliptic-curve` crate dependency to v0.11 ([#466])
- Bump `ecdsa` crate dependency to v0.13 ([#467])

[#435]: https://github.com/RustCrypto/elliptic-curves/pull/435
[#453]: https://github.com/RustCrypto/elliptic-curves/pull/453
[#463]: https://github.com/RustCrypto/elliptic-curves/pull/463
[#466]: https://github.com/RustCrypto/elliptic-curves/pull/466
[#467]: https://github.com/RustCrypto/elliptic-curves/pull/467

## 0.8.0 (2021-06-08)
### Changed
- Bump `elliptic-curve` to v0.10; MSRV 1.51+ ([#349])
- Bump `ecdsa` to v0.12 ([#349])

[#349]: https://github.com/RustCrypto/elliptic-curves/pull/349

## 0.7.0 (2021-04-29)
### Added
- `jwk` feature ([#279])
- `Order` constant ([#328])

### Changed
- Rename `ecdsa::Asn1Signature` to `::DerSignature` ([#288])
- Bump `elliptic-curve` crate dependency to v0.9 ([#293])
- Bump `pkcs8` crate dependency to v0.6 ([#319])
- Bump `ecdsa` crate dependency to v0.11 ([#330])

[#279]: https://github.com/RustCrypto/elliptic-curves/pull/279
[#288]: https://github.com/RustCrypto/elliptic-curves/pull/288
[#293]: https://github.com/RustCrypto/elliptic-curves/pull/293
[#319]: https://github.com/RustCrypto/elliptic-curves/pull/319
[#328]: https://github.com/RustCrypto/elliptic-curves/pull/328
[#330]: https://github.com/RustCrypto/elliptic-curves/pull/330

## 0.6.1 (2020-12-16)
### Fixed
- Trigger docs.rs rebuild with nightly bugfix ([RustCrypto/traits#412])

[RustCrypto/traits#412]: https://github.com/RustCrypto/traits/pull/412

## 0.6.0 (2020-12-16)
### Changed
- Bump `elliptic-curve` dependency to v0.8 ([#260])
- Bump `ecdsa` to v0.10 ([#260])

[#260]: https://github.com/RustCrypto/elliptic-curves/pull/260

## 0.5.0 (2020-12-06)
### Added
- PKCS#8 support ([#243], [#244])

### Changed
- Bump `elliptic-curve` crate dependency to v0.7; MSRV 1.46+ ([#247])
- Bump `ecdsa` crate dependency to v0.9 ([#247])

[#247]: https://github.com/RustCrypto/elliptic-curves/pull/247
[#244]: https://github.com/RustCrypto/elliptic-curves/pull/244
[#243]: https://github.com/RustCrypto/elliptic-curves/pull/243

## 0.4.1 (2020-10-08)
### Added
- `SecretValue` impl when `arithmetic` feature is disabled ([#222])

[#222]: https://github.com/RustCrypto/elliptic-curves/pull/222

## 0.4.0 (2020-09-18)
### Added
- `ecdsa::Asn1Signature` type alias ([#186])

### Changed
- Rename `ElementBytes` => `FieldBytes` ([#176])
- Rename `Curve::ElementSize` => `FieldSize` ([#150])

[#186]: https://github.com/RustCrypto/elliptic-curves/pull/186
[#176]: https://github.com/RustCrypto/elliptic-curves/pull/176
[#150]: https://github.com/RustCrypto/elliptic-curves/pull/150

## 0.3.0 (2020-08-10)
### Added
- ECDSA types ([#73])
- OID support ([#103], [#113])

### Changed
- Bump `elliptic-curve` crate dependency to v0.5 ([#126])

[#73]: https://github.com/RustCrypto/elliptic-curves/pull/73
[#103]: https://github.com/RustCrypto/elliptic-curves/pull/103
[#113]: https://github.com/RustCrypto/elliptic-curves/pull/113
[#126]: https://github.com/RustCrypto/elliptic-curves/pull/126

## 0.2.0 (2020-06-08)
### Changed
- Bump `elliptic-curve` crate dependency to v0.4 ([#39])

[#39]: https://github.com/RustCrypto/elliptic-curves/pull/39

## 0.1.0 (2020-01-15)
- Initial release
