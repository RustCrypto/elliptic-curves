//! Brainpool P-256 elliptic curve (a.k.a. brainpoolP256r1)
//!
//! ## Minimum Supported Rust Version
//!
//! Rust **1.46** or higher.
//!
//! Minimum supported Rust version may be changed in the future, but it will be
//! accompanied with a minor version bump.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_root_url = "https://docs.rs/bp256/0.0.0"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub mod ecdsa;

pub use elliptic_curve;

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

use elliptic_curve::consts::U32;

/// Brainpool P-256 elliptic curve.
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BrainpoolP256;

impl elliptic_curve::Curve for BrainpoolP256 {
    /// 256-bit (32-byte)
    type FieldSize = U32;
}

impl elliptic_curve::weierstrass::Curve for BrainpoolP256 {}

impl elliptic_curve::weierstrass::point::Compression for BrainpoolP256 {
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl elliptic_curve::AlgorithmParameters for BrainpoolP256 {
    const OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new(&[1, 3, 36, 3, 3, 2, 8, 1, 1, 7]);
}

/// Brainpool P-256 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<BrainpoolP256>;

/// Brainpool P-256 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<BrainpoolP256>;

/// Brainpool P-256 secret key.
#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
pub type SecretKey = elliptic_curve::SecretKey<BrainpoolP256>;

/// Bytes containing a Brainpool P-256 secret scalar.
#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
pub type SecretBytes = elliptic_curve::SecretBytes<BrainpoolP256>;

#[cfg(feature = "zeroize")]
impl elliptic_curve::SecretValue for BrainpoolP256 {
    type Secret = SecretBytes;

    /// Parse the secret value from bytes
    fn from_secret_bytes(bytes: &FieldBytes) -> Option<SecretBytes> {
        Some(bytes.clone().into())
    }
}

#[cfg(feature = "zeroize")]
impl elliptic_curve::sec1::ValidatePublicKey for BrainpoolP256 {}
