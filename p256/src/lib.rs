//! NIST P-256 elliptic curve (a.k.a. prime256v1, secp256r1)
//!
//! ## About NIST P-256
//!
//! NIST P-256 is a Weierstrass curve specified in FIPS 186-4: Digital Signature
//! Standard (DSS):
//!
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//!
//! Also known as prime256v1 (ANSI X9.62) and secp256r1 (SECG), it's included in
//! the US National Security Agency's "Suite B" and is widely used in protocols
//! like TLS and the associated X.509 PKI.
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

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/p256/0.4.1"
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
    scalar::{NonZeroScalar, Scalar},
    AffinePoint, ProjectivePoint,
};

#[cfg(all(feature = "arithmetic", feature = "rand"))]
pub use arithmetic::scalar::blinding::BlindedScalar;

use elliptic_curve::consts::U32;

#[cfg(feature = "oid")]
use elliptic_curve::oid::ObjectIdentifier;

/// NIST P-256 elliptic curve.
///
/// This curve is also known as prime256v1 (ANSI X9.62) and secp256r1 (SECG)
/// and is specified in FIPS 186-4: Digital Signature Standard (DSS):
///
/// <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
///
/// It's included in the US National Security Agency's "Suite B" and is widely
/// used in protocols like TLS and the associated X.509 PKI.
///
/// Its equation is `y² = x³ - 3x + b` over a ~256-bit prime field where `b` is
/// the "verifiably random"† constant:
///
/// ```text
/// b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
/// ```
///
/// † *NOTE: the specific origins of this constant have never been fully disclosed
///   (it is the SHA-1 digest of an inexplicable NSA-selected constant)*
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct NistP256;

impl elliptic_curve::Curve for NistP256 {
    /// 256-bit (32-byte)
    type FieldSize = U32;
}

impl elliptic_curve::weierstrass::Curve for NistP256 {}

impl elliptic_curve::point::Compression for NistP256 {
    /// NIST P-256 points are typically uncompressed.
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "oid")]
impl elliptic_curve::Identifier for NistP256 {
    const OID: ObjectIdentifier = ObjectIdentifier::new(&[1, 2, 840, 10045, 3, 1, 7]);
}

/// NIST P-256 Serialized Field Element.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type ElementBytes = elliptic_curve::ElementBytes<NistP256>;

/// NIST P-256 SEC1 Encoded Point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<NistP256>;

/// NIST P-256 Secret Key.
pub type SecretKey = elliptic_curve::SecretKey<NistP256>;
