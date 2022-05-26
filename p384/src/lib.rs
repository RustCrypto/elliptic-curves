#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc = include_str!("../README.md")]

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

#[cfg(feature = "arithmetic")]
mod arithmetic;

#[cfg(feature = "ecdh")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdh")))]
pub mod ecdh;

#[cfg(feature = "ecdsa-core")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa-core")))]
pub mod ecdsa;

#[cfg(feature = "arithmetic")]
pub use arithmetic::{
    affine::AffinePoint,
    projective::ProjectivePoint,
    scalar::{blinded::BlindedScalar, Scalar},
};
#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
pub use elliptic_curve::pkcs8;
pub use elliptic_curve::{self, bigint::U384};
use elliptic_curve::{consts::U49, generic_array::GenericArray};

/// NIST P-384 elliptic curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct NistP384;

impl elliptic_curve::Curve for NistP384 {
    /// 384-bit integer type used for internally representing field elements.
    type UInt = U384;

    /// Order of NIST P-384's elliptic curve group (i.e. scalar modulus).
    const ORDER: U384 = U384::from_be_hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");
}

impl elliptic_curve::PrimeCurve for NistP384 {}

impl elliptic_curve::PointCompression for NistP384 {
    /// NIST P-384 points are typically uncompressed.
    const COMPRESS_POINTS: bool = false;
}

impl elliptic_curve::PointCompaction for NistP384 {
    /// NIST P-384 points are typically uncompressed.
    const COMPACT_POINTS: bool = false;
}

#[cfg(feature = "jwk")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
impl elliptic_curve::JwkParameters for NistP384 {
    const CRV: &'static str = "P-384";
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for NistP384 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.34");
}

/// Compressed SEC1-encoded NIST P-384 curve point.
pub type CompressedPoint = GenericArray<u8, U49>;

/// NIST P-384 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or
/// scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<NistP384>;

/// NIST P-384 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<NistP384>;

/// Non-zero NIST P-384 scalar field element.
#[cfg(feature = "arithmetic")]
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<NistP384>;

/// NIST P-384 public key.
#[cfg(feature = "arithmetic")]
pub type PublicKey = elliptic_curve::PublicKey<NistP384>;

/// NIST P-384 secret key.
pub type SecretKey = elliptic_curve::SecretKey<NistP384>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for NistP384 {}

/// Bit representation of a NIST P-384 scalar field element.
#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
pub type ScalarBits = elliptic_curve::ScalarBits<NistP384>;

#[cfg(feature = "voprf")]
#[cfg_attr(docsrs, doc(cfg(feature = "voprf")))]
impl elliptic_curve::VoprfParameters for NistP384 {
    /// See <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-4.4-1.2>.
    type Hash = sha2::Sha384;

    /// See <https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-08.html#section-4.4-1.3>.
    const ID: u16 = 0x0004;
}
