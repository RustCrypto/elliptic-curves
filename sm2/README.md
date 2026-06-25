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

## PKCS#8 Key Encoding

PKCS#8 is a private key format with support for multiple algorithms. It can be
encoded as binary DER or text PEM.

You can recognize PEM encoded PKCS#8 private keys because they do not have an
algorithm name in the type label, e.g.:

```text
-----BEGIN PRIVATE KEY-----
```

PKCS#8 support is gated under the `pkcs8` feature. The `pem` feature, which is
enabled by default, adds PEM decoding and also enables `pkcs8`.

The same pattern is used by the other curve crates in this repository which
re-export `pkcs8`.

The following traits can be used to decode/encode secret and public keys as
PKCS#8/SPKI. Note that [`pkcs8`] is re-exported from `sm2` when the `pkcs8`
feature is enabled:

- [`pkcs8::DecodePrivateKey`]: decode private keys from PKCS#8
- [`pkcs8::EncodePrivateKey`]: encode private keys to PKCS#8
- [`pkcs8::DecodePublicKey`]: decode public keys from SPKI
- [`pkcs8::EncodePublicKey`]: encode public keys to SPKI

For private keys, [`SecretKey::from_der`] and [`SecretKey::from_pem`] provide
convenience methods which can decode PKCS#8 keys. Use the trait methods above
when the input is expected to be specifically PKCS#8.

### Example

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# #[cfg(feature = "pem")]
# {
use sm2::SecretKey;

// WARNING: Do not hardcode private keys in your source code. This is for demonstration purposes only.
let pem = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgCuPaZjuHC6ATf0yg
7QyjemLm1tjhI4n2N7FMrkAErjChRANCAASw6c/Y5GhbSCoUCrcQZztNCe0ri+Jd
Uo3tPoXlB4jHtdZgdBuMw6+OMkH3DdAEcyUkwufqJxqfK3DN2ZVuklWx
-----END PRIVATE KEY-----"#;
let secret_key = SecretKey::from_pem(pem)?;
# let _ = secret_key;
# }
# Ok(())
# }
```

## About SM2

ShangMi 2 (SM2) is a Weierstrass curve specified in [GM/T 0003-2012]:
Cryptography Industry Standard of the People's Republic of China.

The SM2 cryptosystem is composed of three distinct algorithms:

- [x] **SM2DSA**: digital signature algorithm defined in [GBT.32918.2-2016], [ISO.IEC.14888-3] (SM2-2)
- [ ] **SM2KEP**: key exchange protocol defined in [GBT.32918.3-2016] (SM2-3)
- [x] **SM2PKE**: public key encryption algorithm defined in [GBT.32918.4-2016] (SM2-4)

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

[crate-image]: https://img.shields.io/crates/v/sm2?logo=rust
[crate-link]: https://crates.io/crates/sm2
[docs-image]: https://docs.rs/sm2/badge.svg
[docs-link]: https://docs.rs/sm2/
[build-image]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/sm2.yml/badge.svg
[build-link]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/sm2.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
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
