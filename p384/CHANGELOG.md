# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
