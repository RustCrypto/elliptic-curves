# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.14.0 (UNRELEASED)
## Changed
- Update to `elliptic-curve` v0.14 ([#1011])
- Update to `secdect` v0.3 ([#1084])
- Update to `rand_core` v0.9 ([#1125])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#1125])
- Relax MSRV policy and allow MSRV bumps in patch releases

[#964]: https://github.com/RustCrypto/elliptic-curves/pull/964
[#1011]: https://github.com/RustCrypto/elliptic-curves/pull/1011
[#1084]: https://github.com/RustCrypto/elliptic-curves/pull/1084
[#1125]: https://github.com/RustCrypto/elliptic-curves/pull/1125


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
