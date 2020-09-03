//! K-256 ([secp256k1]) elliptic curve.
//!
//! ## About K-256 (secp256k1)
//!
//! K-256 is a Koblitz curve typically referred to as "[secp256k1]".
//! The "K-256" name follows NIST notation where P = prime fields,
//! B = binary fields, and K = Koblitz curves (defined over F₂).
//!
//! The curve is specified as `secp256k1` by Certicom's SECG in
//! "SEC 2: Recommended Elliptic Curve Domain Parameters":
//!
//! <https://www.secg.org/sec2-v2.pdf>
//!
//! It's primarily notable for usage in Bitcoin and other cryptocurrencies.
//!
//! ## ⚠️ Security Warning
//!
//! The elliptic curve arithmetic contained in this crate has never been
//! independently audited!
//!
//! This crate has been designed with the goal of ensuring that secret-dependent
//! operations are performed in constant time (using the `subtle` crate and
//! constant-time formulas). However, it has not been thoroughly assessed to ensure
//! that generated assembly is constant time on common CPU architectures.
//!
//! USE AT YOUR OWN RISK!
//!
//! ## Minimum Supported Rust Version
//!
//! Rust **1.41** or higher.
//!
//! Minimum supported Rust version can be changed in the future, but it will be
//! done with a minor version bump.
//!
//! [secp256k1]: https://en.bitcoin.it/wiki/Secp256k1

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/k256/0.4.2"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(feature = "arithmetic")]
mod arithmetic;

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
    affine::AffinePoint,
    projective::ProjectivePoint,
    scalar::{NonZeroScalar, Scalar},
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
    type FieldSize = U32;
}

impl elliptic_curve::weierstrass::Curve for Secp256k1 {}

impl elliptic_curve::point::Compression for Secp256k1 {
    /// secp256k1 points are typically compressed.
    const COMPRESS_POINTS: bool = true;
}

#[cfg(feature = "oid")]
impl elliptic_curve::Identifier for Secp256k1 {
    const OID: ObjectIdentifier = ObjectIdentifier::new(&[1, 3, 132, 0, 10]);
}

/// K-256 Serialized Field Element.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type ElementBytes = elliptic_curve::ElementBytes<Secp256k1>;

/// K-256 (secp256k1) SEC1 Encoded Point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<Secp256k1>;

/// K-256 (secp256k1) Secret Key.
pub type SecretKey = elliptic_curve::SecretKey<Secp256k1>;
