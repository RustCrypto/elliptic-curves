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
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub mod arithmetic;

pub use elliptic_curve;

use elliptic_curve::{generic_array::typenum::U32, weierstrass::Curve};

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

impl Curve for NistP256 {
    /// 256-bit (32-byte) private scalar
    type ScalarSize = U32;
}

/// NIST P-256 Secret Key
pub type SecretKey = elliptic_curve::SecretKey<U32>;

/// NIST P-256 Public Key
pub type PublicKey = elliptic_curve::weierstrass::PublicKey<NistP256>;

/// NIST P-256 Compressed Curve Point
pub type CompressedPoint = elliptic_curve::weierstrass::CompressedPoint<NistP256>;

/// NIST P-256 Uncompressed Curve Point
pub type UncompressedPoint = elliptic_curve::weierstrass::UncompressedPoint<NistP256>;
