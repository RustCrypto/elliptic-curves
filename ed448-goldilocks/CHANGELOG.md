# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.14.0 (UNRELEASED)
### Added
- `GroupDigest` impl for `Ed448` and `Decaf448` ([#1287])
- Re-export `LOW_A`, `LOW_B`, `LOW_C` points ([#1304])
- Basic wNAF support ([#1714])
- Implement `MulByGeneratorVartime` trait ([#1729])
- `getrandom` feature ([#1521])
- Implement `crypto_common::Generate` trait ([#1586])

### Changed
- Edition changed to 2024 and MSRV bumped to 1.85 ([#1125])
- Relax MSRV policy and allow MSRV bumps in patch releases
- Relicense as Apache 2.0 + MIT ([#1254])
- Use `crypto-bigint` for internal operations ([#1244])
- Split `Scalar` into `EdwardsScalar` and `DecafScalar` ([#1284])
- Move Edwards and Montgomery curve implementations into submodules ([#1300])
- Use `ff`/`group` v0.14.0 ([#1769])
- Use `shake` instead of `sha3` ([#1764])
- Use `elliptic-curve` v0.14 ([#1849])
- Update dependency on `ed448` to v0.5 ([#1757])
- Update dependency on `signature` to v3 ([#1756])
- Update dependency on `pkcs8` to v0.11 ([#1749])

### Removed
- Empty Ristretto implementation ([#1300])
- `bits` feature ([#1766])

[#1125]: https://github.com/RustCrypto/elliptic-curves/pull/1125
[#1244]: https://github.com/RustCrypto/elliptic-curves/pull/1244
[#1254]: https://github.com/RustCrypto/elliptic-curves/pull/1254
[#1284]: https://github.com/RustCrypto/elliptic-curves/pull/1284
[#1287]: https://github.com/RustCrypto/elliptic-curves/pull/1287
[#1300]: https://github.com/RustCrypto/elliptic-curves/pull/1300
[#1304]: https://github.com/RustCrypto/elliptic-curves/pull/1304
[#1521]: https://github.com/RustCrypto/elliptic-curves/pull/1521
[#1586]: https://github.com/RustCrypto/elliptic-curves/pull/1586
[#1714]: https://github.com/RustCrypto/elliptic-curves/pull/1714
[#1729]: https://github.com/RustCrypto/elliptic-curves/pull/1729
[#1749]: https://github.com/RustCrypto/elliptic-curves/pull/1749
[#1756]: https://github.com/RustCrypto/elliptic-curves/pull/1756
[#1757]: https://github.com/RustCrypto/elliptic-curves/pull/1757
[#1764]: https://github.com/RustCrypto/elliptic-curves/pull/1764
[#1766]: https://github.com/RustCrypto/elliptic-curves/pull/1766
[#1769]: https://github.com/RustCrypto/elliptic-curves/pull/1769
[#1849]: https://github.com/RustCrypto/elliptic-curves/pull/1849

## 0.13.0 (Unreleased)
- Initial import into the `elliptic-curves` workspace ([#1219])

[#1219]: https://github.com/RustCrypto/elliptic-curves/pull/1219
