# [RustCrypto]: Generic Prime Fields

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Generic implementation of prime fields built on [`crypto-bigint`], along with macros for writing
field element newtypes including ones with formally verified arithmetic using [`fiat-crypto`].

[Documentation][docs-link]

## About

A *prime field* is a [finite field] of order 𝑝, where 𝑝 is a prime number. Because 𝑝 is prime, every
non-zero element of the field has a modular inverse.

Prime fields are notable for their use in cryptography, particularly for their use as coordinates
(a.k.a. base field) and the scalar field of elliptic curve implementations.

The implementation provided by this crate is built on [`crypto_bigint::modular`], which provides
a generic implementation of modular arithmetic with a modulus fixed at compile-time.

## Minimum Supported Rust Version (MSRV) Policy

MSRV increases are not considered breaking changes and can happen in patch
releases.

The crate MSRV accounts for all supported targets and crate feature
combinations, excluding explicitly unstable features.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/primefield?logo=rust
[crate-link]: https://crates.io/crates/primefield
[docs-image]: https://docs.rs/primefield/badge.svg
[docs-link]: https://docs.rs/primefield/
[build-image]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/primefield.yml/badge.svg
[build-link]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/primefield.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260040-elliptic-curves

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto/
[`crypto-bigint`]: https://docs.rs/crypto-bigint/
[`crypto_bigint::modular`]: https://docs.rs/crypto-bigint/latest/crypto_bigint/modular/index.html
[`fiat-crypto`]: https://github.com/mit-plv/fiat-crypto
[finite field]: https://en.wikipedia.org/wiki/Finite_field
