# RustCrypto: Elliptic Curves ![Rust Version][rustc-image] [![Project Chat][chat-image]][chat-link] [![dependency status][deps-image]][deps-link]

General purpose Elliptic Curve Cryptography (ECC) support, including types
and traits for representing various elliptic curve forms, scalars, points,
and public/secret keys composed thereof.

All curves reside in the separate crates and implemented using traits from
the [`elliptic-curve`](https://docs.rs/elliptic-curve/) crate.

Crates in this repo do not require the standard library (i.e. `no_std` capable)
and can be easily used for bare-metal or WebAssembly programming.

## Crates

| Name        | Curve              | `arithmetic`? | Crates.io                                                                                     | Documentation                                                                  | Build Status                                                                                                 |
|-------------|--------------------|---------------|-----------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| [`bign256`] | bign-curve256v1    | ✅            | [![crates.io](https://img.shields.io/crates/v/bign256.svg)](https://crates.io/crates/bign256) | [![Documentation](https://docs.rs/bign256/badge.svg)](https://docs.rs/bign256) | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/bign256/badge.svg?branch=master&event=push) |
| [`bp256`]   | brainpoolP256r1/t1 | 🚫            | [![crates.io](https://img.shields.io/crates/v/bp256.svg)](https://crates.io/crates/bp256)     | [![Documentation](https://docs.rs/bp256/badge.svg)](https://docs.rs/bp256)     | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/bp256/badge.svg?branch=master&event=push)   |
| [`bp384`]   | brainpoolP384r1/t1 | 🚫            | [![crates.io](https://img.shields.io/crates/v/bp384.svg)](https://crates.io/crates/bp384)     | [![Documentation](https://docs.rs/bp384/badge.svg)](https://docs.rs/bp384)     | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/bp384/badge.svg?branch=master&event=push)   |
| [`k256`]    | [secp256k1]        | ✅            | [![crates.io](https://img.shields.io/crates/v/k256.svg)](https://crates.io/crates/k256)       | [![Documentation](https://docs.rs/k256/badge.svg)](https://docs.rs/k256)       | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/k256/badge.svg?branch=master&event=push)    |
| [`p224`]    | [NIST P-224]       | 🚧            | [![crates.io](https://img.shields.io/crates/v/p224.svg)](https://crates.io/crates/p224)       | [![Documentation](https://docs.rs/p224/badge.svg)](https://docs.rs/p224)       | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/p224/badge.svg?branch=master&event=push)    |
| [`p256`]    | [NIST P-256]       | ✅            | [![crates.io](https://img.shields.io/crates/v/p256.svg)](https://crates.io/crates/p256)       | [![Documentation](https://docs.rs/p256/badge.svg)](https://docs.rs/p256)       | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/p256/badge.svg?branch=master&event=push)    |
| [`p384`]    | [NIST P-384]       | ✅            | [![crates.io](https://img.shields.io/crates/v/p384.svg)](https://crates.io/crates/p384)       | [![Documentation](https://docs.rs/p384/badge.svg)](https://docs.rs/p384)       | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/p384/badge.svg?branch=master&event=push)    |
| [`p521`]    | [NIST P-521]       | 🚧            | [![crates.io](https://img.shields.io/crates/v/p521.svg)](https://crates.io/crates/p521)       | [![Documentation](https://docs.rs/p521/badge.svg)](https://docs.rs/p521)       | ![build](https://github.com/RustCrypto/elliptic-curves/workflows/p521/badge.svg?branch=master&event=push)    |

NOTE: Some crates contain field/point arithmetic implementations gated under the
`arithmetic` cargo feature as noted above.

Please see our [tracking issue for additional elliptic curves][other-curves]
if you are interested in curves beyond the ones listed here.

## Minimum Supported Rust Version

All crates in this repository support Rust **1.65** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

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

[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg

[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260040-elliptic-curves

[deps-image]: https://deps.rs/repo/github/RustCrypto/elliptic-curves/status.svg

[deps-link]: https://deps.rs/repo/github/RustCrypto/elliptic-curves

[//]: # (crates)

[`bign256`]: https://github.com/RustCrypto/elliptic-curves/tree/master/bign256

[`bp256`]: https://github.com/RustCrypto/elliptic-curves/tree/master/bp256

[`bp384`]: https://github.com/RustCrypto/elliptic-curves/tree/master/bp384

[`k256`]: https://github.com/RustCrypto/elliptic-curves/tree/master/k256

[`p224`]: https://github.com/RustCrypto/elliptic-curves/tree/master/p224

[`p256`]: https://github.com/RustCrypto/elliptic-curves/tree/master/p256

[`p384`]: https://github.com/RustCrypto/elliptic-curves/tree/master/p384

[`p521`]: https://github.com/RustCrypto/elliptic-curves/tree/master/p521

[//]: # (curves)

[secp256k1]: https://neuromancer.sk/std/secg/secp256k1

[NIST P-224]: https://neuromancer.sk/std/nist/P-224

[NIST P-256]: https://neuromancer.sk/std/nist/P-256

[NIST P-384]: https://neuromancer.sk/std/nist/P-384

[NIST P-521]: https://neuromancer.sk/std/nist/P-521

[BIGN P-256]: https://apmi.bsu.by/assets/files/std/bign-spec294.pdf

[//]: # (links)

[other-curves]: https://github.com/RustCrypto/elliptic-curves/issues/114
