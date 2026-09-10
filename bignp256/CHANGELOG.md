# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.14.0 (2026-09-10)
### Added
- ECDH and PKCS#8/PEM support for BIGN keys ([#1046])
- `serde` and `test-vectors` features ([#1062])
- Implement `From<NonZeroScalar>` and `From<&NonZeroScalar>` for `Scalar` ([#1188])
- Implement `TryFrom<Scalar>` for `NonZeroScalar` ([#1193])
- Implement `MultipartSigner` and `MultipartVerifier` ([#1221])
- `getrandom` feature ([#1521])
- Implement `crypto_common::Generate` for `SecretKey` and `SigningKey` ([#1586])
- Variable-time scalar multiplication and linear combinations using wNAF ([#1714], [#1870])
- `swu` feature with BAKE-SWU hash-to-curve support ([#1743])
- Implement `FieldArithmetic` for `BignP256` ([#1833])
- `precomputed-tables` feature ([#1920])
- Optional `crypto-bigint` field and scalar backend via `bignp256_backend="bigint"` ([#1920])

### Changed
- Rename `dsa` module and feature to `ecdsa` ([#1046])
- Use untagged BIGN public key encoding; rename `VerifyingKey::{from_sec1_bytes,to_sec1_bytes}` to `::{from_bytes,to_bytes}` ([#1046])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#1125])
- Relax MSRV policy and allow MSRV bumps in patch releases ([#1125])
- Use `primefield` for field and scalar arithmetic boilerplate ([#1158])
- Regenerate field and scalar backends with `fiat-crypto` v0.1.5 ([#1413])
- Rename `ScalarPrimitive` to `ScalarValue` ([#1417])
- Rename crate from `bign256` to `bignp256` ([#1430])
- Use ECDH types and implementation from `elliptic-curve` ([#1516])
- Make `SigningKey::from_nonzero_scalar` infallible and add conversions between signing keys, secret keys, and non-zero scalars ([#1586])
- Bump `rand_core` dependency to v0.10 ([#1642])
- Rename `EncodedPoint` to `Sec1Point` and update SEC1 conversion APIs ([#1648])
- Bump `digest` dependency to v0.11 ([#1682])
- Use little-endian field, scalar, key, and signature encodings as required by the BIGN specification ([#1684])
- Replace RFC6979 nonce generation with `bign-genk` ([#1684])
- Bump `belt-hash` dependency to v0.2 ([#1700])
- Bump transitive `pkcs8` dependency to v0.11 ([#1749])
- Bump `signature` dependency to v3 ([#1756])
- Bump `elliptic-curve` dependency to v0.14 ([#1849], [#1871])
- Bump `primeorder` dependency to v0.14 ([#1887])
- Wrap `elliptic_curve::{PublicKey, SecretKey}` while retaining BIGN key encoding; rename `SecretKey::as_scalar_primitive` to `::as_scalar_value` ([#1908])
- Bump `bign-genk` dependency to v0.1 ([#1911])

### Fixed
- BIGN curve OID ([#1046])
- PKCS#8 feature gating ([#1655])
- Hash the affine x-coordinate during signature verification ([#1684])
- Secret key zeroization on drop and redaction of secret material in `Debug` output ([#1908])
- Reject the identity point when decoding public keys ([#1908])
- Little-endian scalar handling in variable-time multiplication and linear combinations ([#1913])
- Have `ecdsa` feature enable `digest` ([#1920])

### Removed
- `CompressedPoint` type alias ([#1046])
- `SigningKey::new`: use `From<SecretKey>` instead ([#1586])

[#1046]: https://github.com/RustCrypto/elliptic-curves/pull/1046
[#1062]: https://github.com/RustCrypto/elliptic-curves/pull/1062
[#1125]: https://github.com/RustCrypto/elliptic-curves/pull/1125
[#1158]: https://github.com/RustCrypto/elliptic-curves/pull/1158
[#1188]: https://github.com/RustCrypto/elliptic-curves/pull/1188
[#1193]: https://github.com/RustCrypto/elliptic-curves/pull/1193
[#1221]: https://github.com/RustCrypto/elliptic-curves/pull/1221
[#1413]: https://github.com/RustCrypto/elliptic-curves/pull/1413
[#1417]: https://github.com/RustCrypto/elliptic-curves/pull/1417
[#1430]: https://github.com/RustCrypto/elliptic-curves/pull/1430
[#1516]: https://github.com/RustCrypto/elliptic-curves/pull/1516
[#1521]: https://github.com/RustCrypto/elliptic-curves/pull/1521
[#1586]: https://github.com/RustCrypto/elliptic-curves/pull/1586
[#1642]: https://github.com/RustCrypto/elliptic-curves/pull/1642
[#1648]: https://github.com/RustCrypto/elliptic-curves/pull/1648
[#1655]: https://github.com/RustCrypto/elliptic-curves/pull/1655
[#1682]: https://github.com/RustCrypto/elliptic-curves/pull/1682
[#1684]: https://github.com/RustCrypto/elliptic-curves/pull/1684
[#1700]: https://github.com/RustCrypto/elliptic-curves/pull/1700
[#1714]: https://github.com/RustCrypto/elliptic-curves/pull/1714
[#1743]: https://github.com/RustCrypto/elliptic-curves/pull/1743
[#1749]: https://github.com/RustCrypto/elliptic-curves/pull/1749
[#1756]: https://github.com/RustCrypto/elliptic-curves/pull/1756
[#1833]: https://github.com/RustCrypto/elliptic-curves/pull/1833
[#1849]: https://github.com/RustCrypto/elliptic-curves/pull/1849
[#1870]: https://github.com/RustCrypto/elliptic-curves/pull/1870
[#1871]: https://github.com/RustCrypto/elliptic-curves/pull/1871
[#1887]: https://github.com/RustCrypto/elliptic-curves/pull/1887
[#1908]: https://github.com/RustCrypto/elliptic-curves/pull/1908
[#1911]: https://github.com/RustCrypto/elliptic-curves/pull/1911
[#1913]: https://github.com/RustCrypto/elliptic-curves/pull/1913
[#1920]: https://github.com/RustCrypto/elliptic-curves/pull/1920

## 0.13.1 (2024-01-05)
### Added
- Digital signature algorithm ([#935])

[#935]: https://github.com/RustCrypto/elliptic-curves/pull/935

## 0.13.0 (2023-06-27)
- Initial release
