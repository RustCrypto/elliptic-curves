#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(clippy::needless_range_loop)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! ## `serde` support
//!
//! When the `serde` feature of this crate is enabled, `Serialize` and
//! `Deserialize` are impl'd for the following types:
//!
//! - [`AffinePoint`]
//! - [`Scalar`]
//! - [`ecdsa::VerifyingKey`]
//!
//! Please see type-specific documentation for more information.
//!
//! ## PKCS#8 Key Encoding
//!
//! PKCS#8 is a private key format with support for multiple algorithms. It can be
//! encoded as binary DER or text PEM.
//!
//! You can recognize PEM encoded PKCS#8 private keys because they do not have an
//! algorithm name in the type label, e.g.:
//!
//! ```text
//! -----BEGIN PRIVATE KEY-----
//! ```
//!
//! PKCS#8 support is gated under the `pkcs8` feature. The `pem` feature, which is
//! enabled by default, adds PEM decoding and also enables `pkcs8`.
//!
//! The same pattern is used by the other curve crates in this repository which
//! re-export `pkcs8`.
//!
//! The following traits can be used to decode/encode secret and public keys as
//! PKCS#8/SPKI. Note that [`pkcs8`] is re-exported from `k256` when the `pkcs8`
//! feature is enabled:
//!
//! - [`pkcs8::DecodePrivateKey`]: decode private keys from PKCS#8
//! - [`pkcs8::EncodePrivateKey`]: encode private keys to PKCS#8
//! - [`pkcs8::DecodePublicKey`]: decode public keys from SPKI
//! - [`pkcs8::EncodePublicKey`]: encode public keys to SPKI
//!
//! For private keys, [`SecretKey::from_der`] and [`SecretKey::from_pem`] provide
//! convenience methods which can decode PKCS#8 keys. Use the trait methods above
//! when the input is expected to be specifically PKCS#8.
//!
//! ### Example
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "pem")]
//! # {
//! use k256::SecretKey;
//!
//! // WARNING: Do not hardcode private keys in your source code. This is for demonstration purposes only.
//! let pem = r#"-----BEGIN PRIVATE KEY-----
//! MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg5gaqCR3sHPJeQHw2qXBM
//! 45LTkX+ek6P3OYLcSkrwK2KhRANCAATvt+fomKwK3lN/EyTIgA4OzmlGj0xQuU0w
//! T9scCLkqYa+pYyw+hfpE80apG3HucI2DhwPK8ozPg+TMwQqUmwN6
//! -----END PRIVATE KEY-----"#;
//! let secret_key = SecretKey::from_pem(pem)?;
//! # let _ = secret_key;
//! # }
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "arithmetic")]
mod arithmetic;

#[cfg(feature = "ecdh")]
pub mod ecdh;

#[cfg(feature = "ecdsa-core")]
pub mod ecdsa;

#[cfg(feature = "schnorr")]
pub mod schnorr;

#[cfg(any(feature = "test-vectors", test))]
pub mod test_vectors;

#[cfg(feature = "hash2curve")]
pub use hash2curve;

pub use elliptic_curve::{self, bigint::U256};

#[cfg(feature = "arithmetic")]
pub use arithmetic::{affine::AffinePoint, projective::ProjectivePoint, scalar::Scalar};
#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;
#[cfg(feature = "sha2")]
pub use sha2;

use elliptic_curve::{
    array::Array,
    bigint::Odd,
    consts::{U32, U33, U64},
};

/// Order of the secp256k1 elliptic curve in hexadecimal.
const ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

/// Order of the secp256k1 elliptic curve.
const ORDER: Odd<U256> = Odd::<U256>::from_be_hex(ORDER_HEX);

/// secp256k1 (K-256) elliptic curve.
///
/// Specified in Certicom's SECG in "SEC 2: Recommended Elliptic Curve Domain Parameters":
///
/// <https://www.secg.org/sec2-v2.pdf>
///
/// The curve's equation is `y² = x³ + 7` over a ~256-bit prime field.
///
/// It's primarily notable for usage in Bitcoin and other cryptocurrencies,
/// particularly in conjunction with the Elliptic Curve Digital Signature
/// Algorithm (ECDSA).
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Secp256k1;

impl elliptic_curve::Curve for Secp256k1 {
    /// 32-byte serialized field elements.
    type FieldBytesSize = U32;

    /// 256-bit field modulus.
    type Uint = U256;

    /// Curve order.
    const ORDER: Odd<U256> = ORDER;
}

impl elliptic_curve::PrimeCurve for Secp256k1 {}

impl elliptic_curve::point::PointCompression for Secp256k1 {
    /// secp256k1 points are typically compressed.
    const COMPRESS_POINTS: bool = true;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for Secp256k1 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.10");
}

/// Compressed SEC1-encoded secp256k1 (K-256) curve point.
pub type CompressedPoint = Array<u8, U33>;

/// SEC1-encoded secp256k1 (K-256) curve point.
pub type Sec1Point = elliptic_curve::sec1::Sec1Point<Secp256k1>;

/// secp256k1 (K-256) field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<Secp256k1>;

/// Bytes used by a wide reduction: twice the width of [`FieldBytes`].
pub type WideBytes = Array<u8, U64>;

/// Non-zero secp256k1 (K-256) scalar field element.
#[cfg(feature = "arithmetic")]
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<Secp256k1>;

/// secp256k1 (K-256) public key.
#[cfg(feature = "arithmetic")]
pub type PublicKey = elliptic_curve::PublicKey<Secp256k1>;

/// secp256k1 (K-256) secret key.
pub type SecretKey = elliptic_curve::SecretKey<Secp256k1>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for Secp256k1 {}
