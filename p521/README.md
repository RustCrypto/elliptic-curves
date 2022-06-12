# RustCrypto: NIST P-521 (secp521r1) elliptic curve

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

NIST P-521 elliptic curve (a.k.a. secp521r1) types.

[Documentation][docs-link]

## Stub!

This crate is a placeholder for implementing NIST P-521 in terms of traits
from the [`elliptic-curve`] crate, however no actual implementation work has
been done yet. If you are actually interested in P-521 support, please open
an issue about it.

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

[crate-image]: https://img.shields.io/crates/v/p521.svg
[crate-link]: https://crates.io/crates/p521
[docs-image]: https://docs.rs/p521/badge.svg
[docs-link]: https://docs.rs/p521/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[build-image]: https://github.com/RustCrypto/elliptic-curves/workflows/p521/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/elliptic-curves/actions?query=workflow%3Ap521

[//]: # (general links)

[`elliptic-curve`]: https://github.com/RustCrypto/traits/tree/master/elliptic-curve
