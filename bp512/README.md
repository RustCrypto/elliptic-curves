# [RustCrypto]: Brainpool P-512 elliptic curves

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.

## About

Brainpool P-512 (`brainpoolP512r1` and `brainpoolP512t1`) elliptic curve
types implemented in terms of traits from the [`elliptic-curve`] crate.

The curve parameters are specified in [RFC 5639, Section 3.7].

[Documentation][docs-link]

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

[crate-image]: https://img.shields.io/crates/v/bp512?logo=rust
[crate-link]: https://crates.io/crates/bp512
[docs-image]: https://docs.rs/bp512/badge.svg
[docs-link]: https://docs.rs/bp512/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260040-elliptic-curves
[build-image]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/bp512.yml/badge.svg
[build-link]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/bp512.yml

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto/
[`elliptic-curve`]: https://github.com/RustCrypto/traits/tree/master/elliptic-curve
[RFC 5639, Section 3.7]: https://www.rfc-editor.org/rfc/rfc5639.html#section-3.7
