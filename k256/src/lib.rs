//! K-256 (secp256k1) elliptic curve
//!
//! ## Minimum Supported Rust Version
//!
//! Rust **1.41** or higher.
//!
//! Minimum supported Rust version can be changed in the future, but it will be
//! done with a minor version bump.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(feature = "arithmetic")]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub mod arithmetic;

pub use elliptic_curve;

use elliptic_curve::{generic_array::typenum::U32, weierstrass::Curve};

/// K-256 (secp256k1) elliptic curve.
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
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Secp256k1;

impl Curve for Secp256k1 {
    /// 256-bit (32-byte) private scalar
    type ScalarSize = U32;
}

/// K-256 (secp256k1) Secret Key.
pub type SecretKey = elliptic_curve::SecretKey<U32>;

/// K-256 (secp256k1) Public Key.
pub type PublicKey = elliptic_curve::weierstrass::PublicKey<Secp256k1>;

/// K-256 Scalar Bytes.
///
/// Byte array containing a serialized scalar value (i.e. an integer)
pub type ScalarBytes = elliptic_curve::ScalarBytes<U32>;

/// K-256 Compressed Curve Point.
pub type CompressedPoint = elliptic_curve::weierstrass::CompressedPoint<Secp256k1>;

/// K-256 Uncompressed Curve Point.
pub type UncompressedPoint = elliptic_curve::weierstrass::UncompressedPoint<Secp256k1>;
