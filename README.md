# RustCrypto: Elliptic Curves ![Rust Version][rustc-image]

General purpose Elliptic Curve Cryptography (ECC) support, including types
and traits for representing various elliptic curve forms, scalars, points,
and public/secret keys composed thereof.

All curves reside in the separate crates and implemented using traits from
the [`elliptic-curve`](https://docs.rs/elliptic-curve/) crate. Additionally all
crates do not require the standard library (i.e. `no_std` capable) and can be
easily used for bare-metal or WebAssembly programming.

## Crates

| Name     | Curve      | `arithmetic`? | Crates.io | Documentation | Build |
|----------|------------|---------------|-----------|---------------|-------|
| [`k256`] | [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) | ✅ | [![crates.io](https://img.shields.io/crates/v/k256.svg)](https://crates.io/crates/k256) | [![Documentation](https://docs.rs/k256/badge.svg)](https://docs.rs/k256) | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/k256/badge.svg?branch=master&event=push) |
| [`p256`] | NIST P-256 | ✅ | [![crates.io](https://img.shields.io/crates/v/p256.svg)](https://crates.io/crates/p256) | [![Documentation](https://docs.rs/p256/badge.svg)](https://docs.rs/p256) | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/p256/badge.svg?branch=master&event=push) |
| [`p384`] | NIST P-384 | 🚫 | [![crates.io](https://img.shields.io/crates/v/p384.svg)](https://crates.io/crates/p384) | [![Documentation](https://docs.rs/p384/badge.svg)](https://docs.rs/p384) | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/p384/badge.svg?branch=master&event=push) |
| [`p521`] | NIST P-521 | 🚫 | [![crates.io](https://img.shields.io/crates/v/p521.svg)](https://crates.io/crates/p521) | [![Documentation](https://docs.rs/p521/badge.svg)](https://docs.rs/p521) | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/p521/badge.svg?branch=master&event=push) |

NOTE: Some crates contain field/point arithmetic implementations gated under the
`arithmetic` cargo feature as noted above.

### Other Curves

#### Curve25519

We recommend [curve25519-dalek] for a pure Rust Curve25519 library.

## Minimum Supported Rust Version

All crates in this repository support Rust **1.41** or higher. In future minimum
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

[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg

[//]: # (crates)

[`k256`]: https://github.com/RustCrypto/elliptic-curves/tree/master/k256
[`p256`]: https://github.com/RustCrypto/elliptic-curves/tree/master/p256
[`p384`]: https://github.com/RustCrypto/elliptic-curves/tree/master/p384
[`p521`]: https://github.com/RustCrypto/elliptic-curves/tree/master/p521

[//]: # (general links)

[curve25519-dalek]: https://github.com/dalek-cryptography/curve25519-dalek
