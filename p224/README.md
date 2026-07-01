# [RustCrypto]: NIST P-224 (secp224r1) elliptic curve

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the NIST P-224 (a.k.a. secp224r1) elliptic curve
with support for ECDH, ECDSA signing/verification, and general purpose curve
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

- [Elliptic Curve Diffie-Hellman (ECDH)][ECDH]: gated under the `ecdh` feature.
- [Elliptic Curve Digital Signature Algorithm (ECDSA)][ECDSA]: gated under the
  `ecdsa` feature.

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
PKCS#8/SPKI. Note that [`pkcs8`] is re-exported from `p224` when the `pkcs8`
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
use p224::SecretKey;

// WARNING: Do not hardcode private keys in your source code. This is for demonstration purposes only.
let pem = r#"-----BEGIN PRIVATE KEY-----
MHgCAQAwEAYHKoZIzj0CAQYFK4EEACEEYTBfAgEBBBwlDedvWuvzMLa6xfKlXrs3
V/JbyBNzP/+QPhsdoTwDOgAE5ddW1ppXRtAfa7iV/xaaWSUnNZ2sD4KSVO+bEM8S
yTOPrtKbKLd3E7PjWQj8NDhrm5+CHKtkj3E=
-----END PRIVATE KEY-----"#;
let secret_key = SecretKey::from_pem(pem)?;
# let _ = secret_key;
# }
# Ok(())
# }
```

## About P-224

NIST P-224 is a Weierstrass curve specified in [SP 800-186]:
Recommendations for Discrete Logarithm-based Cryptography:
Elliptic Curve Domain Parameters.

Also known as secp224r1 (SECG).

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

[crate-image]: https://img.shields.io/crates/v/p224?logo=rust
[crate-link]: https://crates.io/crates/p224
[docs-image]: https://docs.rs/p224/badge.svg
[docs-link]: https://docs.rs/p224/
[build-image]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/p224.yml/badge.svg
[build-link]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/p224.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260040-elliptic-curves

[//]: # (general links)

[RustCrypto]: https://github.com/rustcrypto/
[`elliptic-curve`]: https://github.com/RustCrypto/traits/tree/master/elliptic-curve
[ECDH]: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie-Hellman
[ECDSA]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
[SP 800-186]: https://csrc.nist.gov/publications/detail/sp/800-186/final
