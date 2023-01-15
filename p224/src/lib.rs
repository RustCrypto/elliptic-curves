#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

pub use elliptic_curve::{self, bigint::U256};

use elliptic_curve::{consts::U29, generic_array::GenericArray};

/// NIST P-224 elliptic curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct NistP224;

impl elliptic_curve::Curve for NistP224 {
    /// Big integer type used for representing field elements.
    ///
    /// Uses `U256` to allow 4 x 64-bit limbs.
    // TODO(tarcieri): use a `U224` on 32-bit targets?
    type UInt = U256;

    /// Order of NIST P-224's elliptic curve group (i.e. scalar modulus).
    const ORDER: U256 =
        U256::from_be_hex("00000000ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d");
}

impl elliptic_curve::PrimeCurve for NistP224 {}

impl elliptic_curve::PointCompression for NistP224 {
    /// NIST P-224 points are typically uncompressed.
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for NistP224 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.33");
}

/// Compressed SEC1-encoded NIST P-224 curve point.
pub type CompressedPoint = GenericArray<u8, U29>;

/// NIST P-224 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or
/// scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<NistP224>;

/// NIST P-224 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<NistP224>;

/// NIST P-224 secret key.
pub type SecretKey = elliptic_curve::SecretKey<NistP224>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for NistP224 {}

/// Bit representation of a NIST P-224 scalar field element.
#[cfg(feature = "bits")]
pub type ScalarBits = elliptic_curve::ScalarBits<NistP224>;
