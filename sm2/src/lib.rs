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

pub use elliptic_curve;

#[cfg(feature = "arithmetic")]
pub use arithmetic::{scalar::Scalar, AffinePoint, ProjectivePoint};

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

use elliptic_curve::{
    bigint::{ArrayEncoding, U256},
    consts::U32,
    generic_array::{typenum::U33, GenericArray},
    FieldBytesEncoding,
};

/// Order of SM2's elliptic curve group (i.e. scalar modulus) serialized as
/// hexadecimal.
const ORDER_HEX: &str = "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123";

/// SM2 elliptic curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Sm2;

impl elliptic_curve::Curve for Sm2 {
    /// 24-byte serialized field elements.
    type FieldBytesSize = U32;

    /// Big integer type used for representing field elements.
    type Uint = U256;

    /// Order of SM2's elliptic curve group (i.e. scalar modulus).
    const ORDER: U256 = U256::from_be_hex(ORDER_HEX);
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
pub type CompressedPoint = GenericArray<u8, U33>;

/// SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<Sm2>;

/// SM2 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or
/// scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<Sm2>;

impl FieldBytesEncoding<Sm2> for U256 {
    fn decode_field_bytes(field_bytes: &FieldBytes) -> Self {
        U256::from_be_byte_array(*field_bytes)
    }

    fn encode_field_bytes(&self) -> FieldBytes {
        self.to_be_byte_array()
    }
}

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

/// Bit representation of a SM2 scalar field element.
#[cfg(feature = "bits")]
pub type ScalarBits = elliptic_curve::ScalarBits<Sm2>;
