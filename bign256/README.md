# [RustCrypto]: BIGN P-256 (bign-curve256v1) elliptic curve

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the BIGN P-256 (a.k.a. bign-curve256v1) elliptic curve
with support for ECDSA signing/verification, and general purpose curve
arithmetic support implemented in terms of traits from the [`elliptic-curve`]
crate.

[Documentation][docs-link]

## ⚠️ Security Warning

The elliptic curve arithmetic contained in this crate has never been
independently audited!

This crate has been designed with the goal of ensuring that secret-dependent
operations are performed in constant time (using the `subtle` crate and
constant-time formulas). However, it has not been thoroughly assessed to ensure
that generated assembly is constant time on common CPU architectures.

USE AT YOUR OWN RISK!

## Supported Algorithms

## About BIGN P-256

BIGN P-256 is a Weierstrass curve specified in [STB 34.101.45-2013].
Also known as bign-curve256v1.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/bign256?logo=rust
[crate-link]: https://crates.io/crates/bign256
[docs-image]: https://docs.rs/bign256/badge.svg
[docs-link]: https://docs.rs/bign256/
[build-image]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/bign256.yml/badge.svg
[build-link]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/bign256.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260040-elliptic-curves

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto/
[`elliptic-curve`]: https://github.com/RustCrypto/traits/tree/master/elliptic-curve
[ECDH]: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie-Hellman
[ECDSA]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
[STB 34.101.45-2013]: https://apmi.bsu.by/assets/files/std/bign-spec294.pdf
