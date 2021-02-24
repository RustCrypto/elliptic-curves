//! Pure Rust implementation of the [secp256k1] (K-256) elliptic curve,
//! including support for the
//! [Elliptic Curve Digital Signature Algorithm (ECDSA)][ECDSA],
//! [Elliptic Curve Diffie-Hellman (ECDH)][ECDH], and general purpose
//! elliptic curve/field arithmetic which can be used to implement
//! protocols based on group operations.
//!
//! ## About secp256k1 (K-256)
//!
//! secp256k1 is a Koblitz curve commonly used in cryptocurrency applications.
//! The "K-256" name follows NIST notation where P = prime fields,
//! B = binary fields, and K = Koblitz curves.
//!
//! The curve is specified as `secp256k1` by Certicom's SECG in
//! "SEC 2: Recommended Elliptic Curve Domain Parameters":
//!
//! <https://www.secg.org/sec2-v2.pdf>
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
//! Rust **1.46** or higher.
//!
//! Minimum supported Rust version may be changed in the future, but it will be
//! accompanied with a minor version bump.
//!
//! [secp256k1]: https://en.bitcoin.it/wiki/Secp256k1
//! [ECDSA]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
//! [ECDH]: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/k256/0.8.0-pre"
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
    scalar::{NonZeroScalar, Scalar, ScalarBits},
};

#[cfg(feature = "expose-field")]
pub use arithmetic::FieldElement;

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
pub use elliptic_curve::pkcs8;

use elliptic_curve::consts::U32;

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

impl elliptic_curve::weierstrass::PointCompression for Secp256k1 {
    /// secp256k1 points are typically compressed.
    const COMPRESS_POINTS: bool = true;
}

#[cfg(feature = "jwk")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
impl elliptic_curve::JwkParameters for Secp256k1 {
    const CRV: &'static str = "secp256k1";
}

#[cfg(feature = "pkcs8")]
impl elliptic_curve::AlgorithmParameters for Secp256k1 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::parse("1.3.132.0.10");
}

/// Compressed SEC1-encoded secp256k1 (K-256) point.
pub type CompressedPoint = [u8; 33];

/// secp256k1 (K-256) field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<Secp256k1>;

/// SEC1-encoded secp256k1 (K-256) curve point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<Secp256k1>;

/// secp256k1 (K-256) public key.
#[cfg(feature = "arithmetic")]
pub type PublicKey = elliptic_curve::PublicKey<Secp256k1>;

/// secp256k1 (K-256) secret key.
#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
pub type SecretKey = elliptic_curve::SecretKey<Secp256k1>;

/// Bytes containing a secp256k1 secret scalar.
#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
pub type SecretBytes = elliptic_curve::SecretBytes<Secp256k1>;

#[cfg(all(not(feature = "arithmetic"), feature = "zeroize"))]
impl elliptic_curve::SecretValue for Secp256k1 {
    type Secret = SecretBytes;

    /// Parse the secret value from bytes
    fn from_secret_bytes(bytes: &FieldBytes) -> Option<SecretBytes> {
        Some(bytes.clone().into())
    }
}

#[cfg(all(not(feature = "arithmetic"), feature = "zeroize"))]
impl elliptic_curve::sec1::ValidatePublicKey for Secp256k1 {}
