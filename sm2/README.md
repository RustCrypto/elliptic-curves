# [RustCrypto]: SM2 elliptic curve

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the SM2 elliptic curve as defined in the Chinese
national standard [GM/T 0003-2012] as well as [ISO/IEC 14888].

[Documentation][docs-link]

## ⚠️ Security Warning

The elliptic curve arithmetic contained in this crate has never been
independently audited!

This crate has been designed with the goal of ensuring that secret-dependent
operations are performed in constant time (using the `subtle` crate and
constant-time formulas). However, it has not been thoroughly assessed to ensure
that generated assembly is constant time on common CPU architectures.

USE AT YOUR OWN RISK!

## About SM2

ShangMi 2 (SM2) is a Weierstrass curve specified in [GM/T 0003-2012]:
Cryptography Industry Standard of the People's Republic of China.

The SM2 cryptosystem is composed of three distinct algorithms:

- [x] **SM2DSA**: digital signature algorithm defined in [GBT.32918.2-2016], [ISO.IEC.14888-3] (SM2-2)
- [ ] **SM2KEP**: key exchange protocol defined in [GBT.32918.3-2016] (SM2-3)
- [x] **SM2PKE**: public key encryption algorithm defined in [GBT.32918.4-2016] (SM2-4)

## Minimum Supported Rust Version

Rust **1.73** or higher.

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

[crate-image]: https://img.shields.io/crates/v/sm2
[crate-link]: https://crates.io/crates/sm2
[docs-image]: https://docs.rs/sm2/badge.svg
[docs-link]: https://docs.rs/sm2/
[build-image]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/sm2.yml/badge.svg
[build-link]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/sm2.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.73+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260040-elliptic-curves

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto/
[GM/T 0003-2012]: https://www.chinesestandard.net/PDF.aspx/GMT0003.4-2012
[GBT.32918.2-2016]: https://www.chinesestandard.net/PDF.aspx/GBT32918.2-2016
[GBT.32918.3-2016]: https://www.chinesestandard.net/PDF.aspx/GBT32918.3-2016
[GBT.32918.4-2016]: https://www.chinesestandard.net/PDF.aspx/GBT32918.4-2016
[ISO/IEC 14888]: https://www.iso.org/standard/76382.html
[ISO.IEC.14888-3]: https://www.iso.org/standard/76382.html
