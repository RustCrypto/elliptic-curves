# RustCrypto: K-256 (secp256k1) elliptic curve

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

K-256 elliptic curve (a.k.a. [secp256k1]) types implemented in terms of traits
from the [`elliptic-curve`] crate.

Optionally includes an [`arithmetic`] feature providing scalar and
affine/projective point types with support for constant-time scalar
multiplication, which can be used to implement protocols such as [ECDH].

[Documentation][docs-link]

## About K-256 (secp256k1)

K-256 is a Koblitz curve typically referred to as "[secp256k1]".
The "K-256" name follows NIST notation where P = prime fields,
B = binary fields, and K = Koblitz curves (defined over F₂).

The curve is specified as `secp256k1` by Certicom's SECG in
"SEC 2: Recommended Elliptic Curve Domain Parameters":

<https://www.secg.org/sec2-v2.pdf>

It's primarily notable for usage in Bitcoin and other cryptocurrencies,
particularly in conjunction with the
[Elliptic Curve Digital Signature Algorithm (ECDSA)][ECDSA].

## Minimum Supported Rust Version

Rust **1.41** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

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

[crate-image]: https://img.shields.io/crates/v/k256.svg
[crate-link]: https://crates.io/crates/k256
[docs-image]: https://docs.rs/k256/badge.svg
[docs-link]: https://docs.rs/k256/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[build-image]: https://github.com/RustCrypto/elliptic-curves/workflows/k256/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/elliptic-curves/actions?query=workflow%3Ak256

[//]: # (general links)

[secp256k1]: https://en.bitcoin.it/wiki/Secp256k1
[`elliptic-curve`]: https://github.com/RustCrypto/elliptic-curves/tree/master/elliptic-curve-crate
[`arithmetic`]: https://docs.rs/k256/latest/k256/arithmetic/index.html
[ECDH]: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman
[ECDSA]: https://github.com/RustCrypto/signatures/tree/master/ecdsa
