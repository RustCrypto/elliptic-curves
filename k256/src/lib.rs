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
#![cfg_attr(feature = "nightly-bench", feature(test))]

#[cfg(feature = "arithmetic")]
mod arithmetic;
#[cfg(feature = "arithmetic")]
mod mul;

#[cfg(feature = "ecdh")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdh")))]
pub mod ecdh;

#[cfg(feature = "ecdsa-core")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa-core")))]
pub mod ecdsa;

#[cfg(any(feature = "test-vectors", test))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-vectors")))]
pub mod test_vectors;

pub use elliptic_curve;

#[cfg(feature = "arithmetic")]
pub use arithmetic::{
    scalar::{NonZeroScalar, Scalar},
    AffinePoint, ProjectivePoint,
};

use elliptic_curve::consts::U32;

#[cfg(feature = "oid")]
use elliptic_curve::oid::ObjectIdentifier;

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

impl elliptic_curve::Curve for Secp256k1 {
    /// 256-bit (32-byte)
    type ElementSize = U32;
}

impl elliptic_curve::weierstrass::Curve for Secp256k1 {
    /// secp256k1 points are typically compressed.
    const COMPRESS_POINTS: bool = true;
}

#[cfg(feature = "oid")]
impl elliptic_curve::Identifier for Secp256k1 {
    const OID: ObjectIdentifier = ObjectIdentifier::new(&[1, 3, 132, 0, 10]);
}

/// K-256 (secp256k1) Secret Key.
pub type SecretKey = elliptic_curve::SecretKey<Secp256k1>;

/// K-256 (secp256k1) Public Key.
pub type PublicKey = elliptic_curve::weierstrass::PublicKey<Secp256k1>;

/// K-256 Serialized Field Element.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type ElementBytes = elliptic_curve::ElementBytes<Secp256k1>;

/// K-256 Compressed Curve Point.
pub type CompressedPoint = elliptic_curve::weierstrass::CompressedPoint<Secp256k1>;

/// K-256 Uncompressed Curve Point.
pub type UncompressedPoint = elliptic_curve::weierstrass::UncompressedPoint<Secp256k1>;
