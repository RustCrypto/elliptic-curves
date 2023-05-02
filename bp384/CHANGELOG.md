# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.6.1 (2023-04-16)
### Added
- WIP `arithmetic` implementation ([#869], [#872], [#873], [#875], [#877])

[#869]: https://github.com/RustCrypto/elliptic-curves/pull/869
[#872]: https://github.com/RustCrypto/elliptic-curves/pull/872
[#873]: https://github.com/RustCrypto/elliptic-curves/pull/873
[#875]: https://github.com/RustCrypto/elliptic-curves/pull/875
[#877]: https://github.com/RustCrypto/elliptic-curves/pull/877

## 0.6.0 (2023-03-02)
### Added
- `FieldBytesEncoding` trait impls ([#732])

### Changed
- Bump `elliptic-curve` dependency to v0.13 ([#770])
- Bump `ecdsa` to v0.16 ([#770])

[#732]: https://github.com/RustCrypto/elliptic-curves/pull/732
[#770]: https://github.com/RustCrypto/elliptic-curves/pull/770

## 0.5.0 (2023-01-15)
### Added
- `alloc` feature ([#670])

### Changed
- Use weak feature activation; MSRV 1.60 ([#701])
- Bump `ecdsa` dependency to v0.15 ([#713])

[#670]: https://github.com/RustCrypto/elliptic-curves/pull/670
[#701]: https://github.com/RustCrypto/elliptic-curves/pull/701
[#713]: https://github.com/RustCrypto/elliptic-curves/pull/713

## 0.4.0 (2022-05-09)
### Changed
- Have `pkcs8` feature activate `ecdsa/pkcs8` ([#538])
- Bump `elliptic-curve` to v0.12 ([#544])
- Bump `ecdsa` to v0.14 ([#544])

[#538]: https://github.com/RustCrypto/elliptic-curves/pull/538
[#544]: https://github.com/RustCrypto/elliptic-curves/pull/544

## 0.3.0 (2021-12-14)
### Added
- `serde` feature ([#463])

### Changed
- Rust 2021 edition upgrade; MSRV 1.56+ ([#453])
- Bump `elliptic-curve` crate dependency to v0.11 ([#466])
- Bump `ecdsa` crate dependency to v0.13 ([#467])

[#453]: https://github.com/RustCrypto/elliptic-curves/pull/453
[#463]: https://github.com/RustCrypto/elliptic-curves/pull/463
[#466]: https://github.com/RustCrypto/elliptic-curves/pull/466
[#467]: https://github.com/RustCrypto/elliptic-curves/pull/467

## 0.2.0 (2021-06-08)
### Changed
- Bump `elliptic-curve` to v0.10; MSRV 1.51+ ([#349])
- Bump `ecdsa` to v0.12 ([#349])

[#349]: https://github.com/RustCrypto/elliptic-curves/pull/349

## 0.1.0 (2021-04-29)
### Added
- `Order` constant ([#328])

### Changed
- Bump `ecdsa` crate dependency to v0.11 ([#330])

[#328]: https://github.com/RustCrypto/elliptic-curves/pull/328
[#330]: https://github.com/RustCrypto/elliptic-curves/pull/330

## 0.0.2 (2021-03-22)
### Changed
- Bump `base64ct`, `ecdsa`, `elliptic-curve`, and `pkcs8`; MSRV 1.47+ ([#318])

[#318]: https://github.com/RustCrypto/elliptic-curves/pull/318

## 0.0.1 (2021-02-11) [YANKED]
- Initial release
