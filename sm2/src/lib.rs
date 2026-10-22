#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::implicit_saturating_sub,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! ## Backends
//!
//! This crate has support for two different field arithmetic backends which can be selected using
//! `cfg(sm2_backend)`, e.g. to select the `bigint` backend:
//!
//! ```console
//! $ RUSTFLAGS='--cfg sm2_backend="bigint"' cargo test
//! ```
//!
//! Or it can be set through [`.cargo/config`][buildrustflags]:
//!
//! ```toml
//! [build]
//! rustflags = ['--cfg', 'sm2_backend="bigint"']
//! ```
//!
//! The available backends are:
//! - `bigint`: experimental backend provided by [crypto-bigint]. May offer better performance in
//!   some cases along with smaller code size, but might also have bugs.
//! - `fiat` (default): formally verified implementation synthesized by [fiat-crypto] which should
//!   be correct for all inputs (though there's a possibility of bugs in the code which glues to it)
//!
//! [buildrustflags]: https://doc.rust-lang.org/cargo/reference/config.html#buildrustflags
//! [crypto-bigint]: https://github.com/RustCrypto/crypto-bigint
//! [fiat-crypto]: https://github.com/mit-plv/fiat-crypto
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
//! PKCS#8/SPKI. Note that [`pkcs8`] is re-exported from `sm2` when the `pkcs8`
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
//! use sm2::SecretKey;
//!
//! // WARNING: Do not hardcode private keys in your source code. This is for demonstration purposes only.
//! let pem = r#"-----BEGIN PRIVATE KEY-----
//! MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgCuPaZjuHC6ATf0yg
//! 7QyjemLm1tjhI4n2N7FMrkAErjChRANCAASw6c/Y5GhbSCoUCrcQZztNCe0ri+Jd
//! Uo3tPoXlB4jHtdZgdBuMw6+OMkH3DdAEcyUkwufqJxqfK3DN2ZVuklWx
//! -----END PRIVATE KEY-----"#;
//! let secret_key = SecretKey::from_pem(pem)?;
//! # let _ = secret_key;
//! # }
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "alloc")]
#[allow(unused_extern_crates)]
extern crate alloc;

#[cfg(feature = "dsa")]
pub mod dsa;
#[cfg(feature = "pke")]
pub mod pke;

#[cfg(feature = "arithmetic")]
mod arithmetic;
#[cfg(feature = "dsa")]
mod distid;

pub use elliptic_curve::{self, bigint::U256};

#[cfg(feature = "arithmetic")]
pub use arithmetic::{AffinePoint, ProjectivePoint, scalar::Scalar};

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

use elliptic_curve::{
    array::Array,
    bigint::Odd,
    consts::{U32, U33, U65},
};

#[cfg(feature = "dsa")]
use crate::distid::DistId;

/// Order of SM2's elliptic curve group (i.e. scalar modulus) serialized as
/// hexadecimal.
const ORDER_HEX: &str = "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123";

/// SM3 hash output.
#[cfg(feature = "dsa")]
type Hash = sm3::digest::Output<sm3::Sm3>;

/// SM2 elliptic curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Sm2;

impl elliptic_curve::Curve for Sm2 {
    /// 24-byte serialized field elements.
    type FieldBytesSize = U32;

    /// Big integer type used for representing field elements.
    type Uint = U256;

    /// Order of SM2's elliptic curve group (i.e. scalar modulus).
    const ORDER: Odd<U256> = Odd::<U256>::from_be_hex(ORDER_HEX);
}

impl elliptic_curve::PrimeCurve for Sm2 {}

impl elliptic_curve::point::PointCompression for Sm2 {
    /// SM2 points are typically uncompressed.
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for Sm2 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.2.156.10197.1.301");
}

/// Compressed SEC1-encoded curve point.
pub type CompressedPoint = Array<u8, U33>;

/// Uncompressed SEC1-encoded curve point.
pub type UncompressedPoint = Array<u8, U65>;

/// SEC1 encoded point.
pub type Sec1Point = elliptic_curve::sec1::Sec1Point<Sm2>;

/// SM2 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or
/// scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<Sm2>;

/// Size of a SM2 field element serialized as bytes.
pub type FieldBytesSize = elliptic_curve::FieldBytesSize<Sm2>;

/// Non-zero scalar field element.
#[cfg(feature = "arithmetic")]
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<Sm2>;

/// SM2 public key: wrapper type for an elliptic curve point.
#[cfg(feature = "arithmetic")]
pub type PublicKey = elliptic_curve::PublicKey<Sm2>;

/// SM2 secret key: wrapper point for a secret scalar.
pub type SecretKey = elliptic_curve::SecretKey<Sm2>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for Sm2 {}
