# [RustCrypto]: wNAF scalar multiplication

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

wNAF (w-ary non-adjacent form) variable-time scalar multiplication implemented generically
over elliptic curve groups, including multiscalar multiplication using Straus's interleaved window
method.

[Documentation][docs-link]

## About

wNAF is a signed-digit representation of a scalar with a minimal number of non-zero digits,
reducing the number of costly group additions required during the double-and-add loop.

The core idea is to represent a scalar `k` as a sequence of digits in:

```text
{-(2^(w-1)-1), ..., -1, 0, 1, ..., 2^(w-1)-1}
```

such that no two consecutive digits are non-zero.

A configurable window size trades memory for speed: a larger window precomputes more multiples
of the base point (a table of `2^(w-2)` entries) but requires fewer group additions per-bit of
the scalar.

## ⚠️ Security Warning

wNAF scalar multiplications should NOT be used with secret scalar values (i.e. elliptic curve
private keys) because they are variable-time and can leak the secret value.

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

[crate-image]: https://img.shields.io/crates/v/wnaf?logo=rust
[crate-link]: https://crates.io/crates/wnaf
[docs-image]: https://docs.rs/wnaf/badge.svg
[docs-link]: https://docs.rs/wnaf/
[build-image]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/wnaf.yml/badge.svg
[build-link]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/wnaf.yml
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
