//! NIST P-256 elliptic curve (a.k.a. prime256v1, secp256r1)
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
mod arithmetic;

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
    type ElementSize = U32;
}

impl elliptic_curve::weierstrass::Curve for NistP256 {}

#[cfg(feature = "oid")]
impl elliptic_curve::Identifier for NistP256 {
    const OID: ObjectIdentifier = ObjectIdentifier::new(&[1, 2, 840, 10045, 3, 1, 7]);
}

/// NIST P-256 Secret Key
pub type SecretKey = elliptic_curve::SecretKey<NistP256>;

/// NIST P-256 Public Key
pub type PublicKey = elliptic_curve::weierstrass::PublicKey<NistP256>;

/// NIST P-256 Scalar Bytes.
///
/// Byte array containing a serialized scalar value (i.e. an integer)
pub type ScalarBytes = elliptic_curve::ScalarBytes<NistP256>;

/// NIST P-256 Compressed Curve Point
pub type CompressedPoint = elliptic_curve::weierstrass::CompressedPoint<NistP256>;

/// NIST P-256 Uncompressed Curve Point
pub type UncompressedPoint = elliptic_curve::weierstrass::UncompressedPoint<NistP256>;
