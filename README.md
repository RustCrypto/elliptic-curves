# RustCrypto: Elliptic Curves

[![Build Status][build-image]][build-link]
[![Dependency Status][deps-image]][deps-link]
![Rust Version][rustc-image]

General purpose Elliptic Curve Cryptography (ECC) support, including types
and traits for representing various elliptic curve forms, scalars, points,
and public/secret keys composed thereof.

All curves reside in the separate crates and implemented using traits from
the [`elliptic-curve`](https://docs.rs/elliptic-curve/) crate. Additionally all
crates do not require the standard library (i.e. `no_std` capable) and can be
easily used for bare-metal or WebAssembly programming.

## Minimum Supported Rust Version

All crates in this repository support Rust **1.37** or higher. In future minimum
supported Rust version can be changed, but it will be done with the minor
version bump.

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

[build-image]: https://travis-ci.org/RustCrypto/elliptic-curve.svg?branch=master
[build-link]: https://travis-ci.org/RustCrypto/elliptic-curve
[deps-image]: https://deps.rs/repo/github/RustCrypto/elliptic-curve/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/elliptic-curve
[rustc-image]: https://img.shields.io/badge/rustc-1.37+-blue.svg
