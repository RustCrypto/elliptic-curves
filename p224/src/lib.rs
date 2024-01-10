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

#[cfg(feature = "ecdh")]
pub mod ecdh;

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
    consts::{U28, U29},
    FieldBytesEncoding,
};

#[cfg(target_pointer_width = "32")]
pub use elliptic_curve::bigint::U224 as Uint;

#[cfg(target_pointer_width = "64")]
use elliptic_curve::bigint::U256 as Uint;

/// Order of NIST P-224's elliptic curve group (i.e. scalar modulus) in hexadecimal.
#[cfg(any(target_pointer_width = "32", feature = "arithmetic"))]
const ORDER_HEX: &str = "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d";

/// NIST P-224 elliptic curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct NistP224;

impl elliptic_curve::Curve for NistP224 {
    /// 28-byte serialized field elements.
    type FieldBytesSize = U28;

    /// Big integer type used for representing field elements.
    type Uint = Uint;

    /// Order of NIST P-224's elliptic curve group (i.e. scalar modulus).
    #[cfg(target_pointer_width = "32")]
    const ORDER: Uint = Uint::from_be_hex(ORDER_HEX);

    /// Order of NIST P-224's elliptic curve group (i.e. scalar modulus).
    #[cfg(target_pointer_width = "64")]
    const ORDER: Uint =
        Uint::from_be_hex("00000000ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d");
}

impl elliptic_curve::PrimeCurve for NistP224 {}

impl elliptic_curve::point::PointCompression for NistP224 {
    /// NIST P-224 points are typically uncompressed.
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for NistP224 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.33");
}

/// Blinded scalar.
#[cfg(feature = "arithmetic")]
pub type BlindedScalar = elliptic_curve::scalar::BlindedScalar<NistP224>;

/// Compressed SEC1-encoded NIST P-224 curve point.
pub type CompressedPoint = Array<u8, U29>;

/// NIST P-224 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<NistP224>;

/// NIST P-224 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or
/// scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<NistP224>;

impl FieldBytesEncoding<NistP224> for Uint {}

/// Non-zero NIST P-256 scalar field element.
#[cfg(feature = "arithmetic")]
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<NistP224>;

/// NIST P-224 public key.
#[cfg(feature = "arithmetic")]
pub type PublicKey = elliptic_curve::PublicKey<NistP224>;

/// NIST P-224 secret key.
pub type SecretKey = elliptic_curve::SecretKey<NistP224>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for NistP224 {}

/// Bit representation of a NIST P-224 scalar field element.
#[cfg(feature = "bits")]
pub type ScalarBits = elliptic_curve::scalar::ScalarBits<NistP224>;
