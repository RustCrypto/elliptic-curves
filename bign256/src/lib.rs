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

pub mod arithmetic;

#[cfg(feature = "ecdsa-core")]
mod ecdsa;

pub use elliptic_curve;

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

pub use elliptic_curve::{consts::U32, generic_array::GenericArray, FieldBytesEncoding};

pub use elliptic_curve::bigint::U256 as Uint;

pub use arithmetic::{scalar::Scalar, AffinePoint, ProjectivePoint};

/// Order of BIGN P-256's elliptic curve group (i.e. scalar modulus) in hexadecimal.
const ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD95C8ED60DFB4DFC7E5ABF99263D6607";

/// BIGN P-256 elliptic curve.
///
/// This curve is also known as bign-curve256v1
/// and is specified in [STB 34.101.45-2013]:
/// Recommendations for Discrete Logarithm-based Cryptography:
/// Elliptic Curve Domain Parameters.
///
///
/// Its equation is `y² = x³ + ax + b` over a ~256-bit prime field.
///
/// ```text
/// a = 115792089237316195423570985008687907853269984665640564039457584007913129639744
/// b = 54189945433829174764701416670523239872420438478408031144987871676190519198705
/// ```
///
/// [STB 34.101.45-2013]: https://apmi.bsu.by/assets/files/std/bign-spec294.pdf
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BignP256;

impl elliptic_curve::Curve for BignP256 {
    /// 256-bit integer type used for internally representing field elements.
    type FieldBytesSize = U32;
    type Uint = Uint;

    /// Order of BIGN P-256's elliptic curve group (i.e. scalar modulus).
    const ORDER: Uint = Uint::from_be_hex(ORDER_HEX);
}

impl elliptic_curve::PrimeCurve for BignP256 {}

impl elliptic_curve::point::PointCompression for BignP256 {
    /// BIGN P-256 points are typically uncompressed.
    const COMPRESS_POINTS: bool = false;
}

impl elliptic_curve::point::PointCompaction for BignP256 {
    /// BIGN P-256 points are typically uncompressed.
    const COMPACT_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for BignP256 {
    const OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.45.1");
}

/// Compressed SEC1-encoded BIGN P256 curve point.
pub type CompressedPoint = GenericArray<u8, U32>;

/// BIGN P-256 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<BignP256>;

/// BIGN P-256 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<BignP256>;

impl FieldBytesEncoding<BignP256> for Uint {}

/// BIGN P-256 public key.
pub type PublicKey = elliptic_curve::PublicKey<BignP256>;

/// BIGN P-256 secret key.
pub type SecretKey = elliptic_curve::SecretKey<BignP256>;

/// Bit representation of a BIGN P-256 scalar field element.
#[cfg(feature = "bits")]
pub type ScalarBits = elliptic_curve::ScalarBits<BignP256>;
