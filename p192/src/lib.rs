#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(feature = "arithmetic")]
mod arithmetic;

#[cfg(feature = "ecdsa-core")]
pub mod ecdsa;

#[cfg(any(feature = "test-vectors", test))]
pub mod test_vectors;

pub use elliptic_curve;

#[cfg(feature = "arithmetic")]
pub use arithmetic::{scalar::Scalar, AffinePoint, ProjectivePoint};

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

use elliptic_curve::{
    array::Array,
    bigint::{ArrayEncoding, U192},
    consts::{U24, U25},
    FieldBytesEncoding,
};

const ORDER_HEX: &str = "ffffffffffffffffffffffff99def836146bc9b1b4d22831";

/// NIST P-192 elliptic curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct NistP192;

impl elliptic_curve::Curve for NistP192 {
    /// 24-byte serialized field elements.
    type FieldBytesSize = U24;

    /// Big integer type used for representing field elements.
    type Uint = U192;

    /// Order of NIST P-192's elliptic curve group (i.e. scalar modulus).
    const ORDER: U192 = U192::from_be_hex(ORDER_HEX);
}

impl elliptic_curve::PrimeCurve for NistP192 {}

impl elliptic_curve::point::PointCompression for NistP192 {
    /// NIST P-192 points are typically uncompressed.
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for NistP192 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.1");
}

/// Compressed SEC1-encoded NIST P-192 curve point.
pub type CompressedPoint = Array<u8, U25>;

/// NIST P-192 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<NistP192>;

/// NIST P-192 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or
/// scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<NistP192>;

impl FieldBytesEncoding<NistP192> for U192 {
    fn decode_field_bytes(field_bytes: &FieldBytes) -> Self {
        U192::from_be_byte_array(*field_bytes)
    }

    fn encode_field_bytes(&self) -> FieldBytes {
        self.to_be_byte_array()
    }
}

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for NistP192 {}

/// Bit representation of a NIST P-192 scalar field element.
#[cfg(feature = "bits")]
pub type ScalarBits = elliptic_curve::scalar::ScalarBits<NistP192>;
