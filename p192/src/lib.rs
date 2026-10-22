#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
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

//! ## PKCS#8 Key Encoding
//!
//! PKCS#8 is a private key format with support for multiple algorithms. It can be
//! encoded as binary DER or text PEM.
//!
//! You can recognize PEM encoded PKCS#8 private keys because they do not have an
//! algorithm name in the type label, e.g.:
//!
//! ```text
//! -----BEGIN PRIVATE KEY-----
//! ```
//!
//! PKCS#8 support is gated under the `pkcs8` feature. The `pem` feature, which is
//! enabled by default, adds PEM decoding and also enables `pkcs8`.
//!
//! The same pattern is used by the other curve crates in this repository which
//! re-export `pkcs8`.
//!
//! The following traits can be used to decode/encode secret and public keys as
//! PKCS#8/SPKI. Note that [`pkcs8`] is re-exported from `p192` when the `pkcs8`
//! feature is enabled:
//!
//! - [`pkcs8::DecodePrivateKey`]: decode private keys from PKCS#8
//! - [`pkcs8::EncodePrivateKey`]: encode private keys to PKCS#8
//! - [`pkcs8::DecodePublicKey`]: decode public keys from SPKI
//! - [`pkcs8::EncodePublicKey`]: encode public keys to SPKI
//!
//! For public keys, you can use the traits above via the generic `elliptic_curve::PublicKey`
//! type when the input is expected to be specifically SPKI.
//!
//! ### Example
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "pem")]
//! # {
//! use p192::elliptic_curve::PublicKey;
//! use p192::NistP192;
//! use p192::pkcs8::DecodePublicKey;
//!
//! // WARNING: Do not hardcode public keys in your source code. This is for demonstration purposes only.
//! let pem = r#"-----BEGIN PUBLIC KEY-----
//! MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAE/xW9cn1Y25+dj7qzy7gvirEF+jIV
//! O0h4q4osrY+F1QFz7XIjwEuHQ6+GyiY9n1t1
//! -----END PUBLIC KEY-----"#;
//! let public_key = PublicKey::<NistP192>::from_public_key_pem(pem)?;
//! # let _ = public_key;
//! # }
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "arithmetic")]
mod arithmetic;

#[cfg(feature = "ecdsa-core")]
pub mod ecdsa;

#[cfg(any(feature = "test-vectors", test))]
pub mod test_vectors;

pub use elliptic_curve;

#[cfg(feature = "arithmetic")]
pub use arithmetic::{AffinePoint, ProjectivePoint, scalar::Scalar};

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

use elliptic_curve::{
    array::Array,
    bigint::{Odd, U192},
    consts::{U24, U25},
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
    const ORDER: Odd<U192> = Odd::<U192>::from_be_hex(ORDER_HEX);
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
pub type Sec1Point = elliptic_curve::sec1::Sec1Point<NistP192>;

/// NIST P-192 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or
/// scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<NistP192>;

/// Non-zero NIST P-192 scalar field element.
#[cfg(feature = "arithmetic")]
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<NistP192>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for NistP192 {}
