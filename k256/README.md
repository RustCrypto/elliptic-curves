# [RustCrypto]: secp256k1 (K-256) elliptic curve

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

[secp256k1] (a.k.a. K-256) elliptic curve library written in pure Rust with
support for [ECDSA] signing/verification/public-key recovery, Taproot
[Schnorr signatures] as defined in BIP340, Elliptic Curve Diffie-Hellman (ECDH),
and general-purpose secp256k1 elliptic curve group operations which can be used
to implement arbitrary group-based protocols.

Uses traits and base types from the [`elliptic-curve`] crate.

Optionally includes a secp256k1 [`arithmetic`] feature providing scalar and
point types (projective/affine) with support for constant-time scalar
multiplication. Additionally, implements traits from the [`group`] crate
which can be used to generically construct group-based protocols.

[Documentation][docs-link]

## Security Notes

This crate has been [audited by NCC Group], which found a high severity issue
in the ECDSA/secp256k1 implementation and another high severity issue in the
Schnorr/secp256k1 signature implementation, both of which have since been
corrected. We would like to thank [Entropy] for funding the audit.

This crate has been designed with the goal of ensuring that secret-dependent
secp256k1 operations are performed in constant time (using the `subtle` crate
and constant-time formulas). However, it is not suitable for use on processors
with a variable-time multiplication operation (e.g. short circuit on
multiply-by-zero / multiply-by-one, such as certain 32-bit PowerPC CPUs and
some non-ARM microcontrollers).

USE AT YOUR OWN RISK!

## Supported Algorithms

- [Elliptic Curve Diffie-Hellman (ECDH)][ECDH]: gated under the `ecdh` feature.
  Note that this is technically ephemeral secp256k1 Diffie-Hellman
  (a.k.a. ECDHE)
- [Elliptic Curve Digital Signature Algorithm (ECDSA)][ECDSA]: gated under the
  `ecdsa` feature. Support for ECDSA/secp256k1 signing and verification,
  applying [low-S normalization (BIP 0062)][BIP0062] as used in
  consensus-critical applications, and additionally supports secp256k1
  public-key recovery from ECDSA signatures (as used by e.g. Ethereum)
- Taproot [Schnorr signatures] (as defined in [BIP0340]): next-generation
  signature algorithm based on group operations enabling elegant higher-level
  constructions like multisignatures.

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
PKCS#8/SPKI. Note that [`pkcs8`] is re-exported from `k256` when the `pkcs8`
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
use k256::SecretKey;

// WARNING: Do not hardcode private keys in your source code. This is for demonstration purposes only.
let pem = r#"-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg5gaqCR3sHPJeQHw2qXBM
45LTkX+ek6P3OYLcSkrwK2KhRANCAATvt+fomKwK3lN/EyTIgA4OzmlGj0xQuU0w
T9scCLkqYa+pYyw+hfpE80apG3HucI2DhwPK8ozPg+TMwQqUmwN6
-----END PRIVATE KEY-----"#;
let secret_key = SecretKey::from_pem(pem)?;
# let _ = secret_key;
# }
# Ok(())
# }
```

## About secp256k1 (K-256)

[secp256k1] is a Koblitz curve commonly used in cryptocurrency applications.
The "K-256" name follows NIST notation where P = prime fields,
B = binary fields, and K = Koblitz curves.

The curve is specified as `secp256k1` by Certicom's SECG in
"SEC 2: Recommended Elliptic Curve Domain Parameters":

<https://www.secg.org/sec2-v2.pdf>

secp256k1 is primarily notable for usage in Bitcoin and other cryptocurrencies,
particularly in conjunction with the
[Elliptic Curve Digital Signature Algorithm (ECDSA)][ECDSA].
Owing to its wide deployment in these applications, secp256k1 is one of the
most popular and commonly used elliptic curves.

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

[crate-image]: https://img.shields.io/crates/v/k256?logo=rust
[crate-link]: https://crates.io/crates/k256
[docs-image]: https://docs.rs/k256/badge.svg
[docs-link]: https://docs.rs/k256/
[build-image]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/k256.yml/badge.svg
[build-link]: https://github.com/RustCrypto/elliptic-curves/actions/workflows/k256.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260040-elliptic-curves

[//]: # (links)

[RustCrypto]: https://github.com/RustCrypto/
[secp256k1]: https://en.bitcoin.it/wiki/Secp256k1
[`elliptic-curve`]: https://github.com/RustCrypto/traits/tree/master/elliptic-curve
[`arithmetic`]: https://docs.rs/k256/latest/k256/arithmetic/index.html
[`group`]: https://github.com/zkcrypto/group
[ECDH]: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie-Hellman
[ECDSA]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
[Schnorr signatures]: https://en.wikipedia.org/wiki/Schnorr_signature
[audited by NCC Group]: https://www.nccgroup.com/us/research-blog/public-report-entropyrust-cryptography-review/
[Entropy]: https://entropy.xyz/
[BIP0062]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
[BIP0340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
