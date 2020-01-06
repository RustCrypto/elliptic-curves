//! NIST P-256 elliptic curve (a.k.a. prime256v1, secp256r1)
//!
//! ## Minimum Supported Rust Version
//!
//! Rust **1.34** or higher.
//!
//! Minimum supported Rust version can be changed in the future, but it will be
//! done with a minor version bump.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]

#[cfg(feature = "arithmetic")]
pub mod arithmetic;

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

/// NIST P-256 secret keys
pub type SecretKey = elliptic_curve::SecretKey<<NistP256 as Curve>::ScalarSize>;

/// NIST P-256 public keys
pub type PublicKey = elliptic_curve::weierstrass::PublicKey<NistP256>;
