//! NIST P-384 elliptic curve (a.k.a. secp384r1)
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

use elliptic_curve::{generic_array::typenum::U48, weierstrass::Curve};

/// NIST P-384 elliptic curve.
///
/// This curve is also known as secp384r1 (SECG) and is specified in
/// FIPS 186-4: Digital Signature Standard (DSS):
///
/// <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
///
/// It's included in the US National Security Agency's "Suite B" and is widely
/// used in protocols like TLS and the associated X.509 PKI.
///
/// Its equation is `y² = x³ - 3x + b` over a ~384-bit prime field where `b` is
/// the "verifiably random"† constant:
///
/// ```text
/// b = 2758019355995970587784901184038904809305690585636156852142
///     8707301988689241309860865136260764883745107765439761230575
/// ```
///
/// † *NOTE: the specific origins of this constant have never been fully disclosed
///   (it is the SHA-1 digest of an inexplicable NSA-selected constant)*
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct NistP384;

impl Curve for NistP384 {
    /// 384-bit (48-byte) private scalar
    type ScalarSize = U48;
}

/// NIST P-384 secret keys
pub type SecretKey = elliptic_curve::SecretKey<<NistP384 as Curve>::ScalarSize>;

/// NIST P-384 public keys
pub type PublicKey = elliptic_curve::weierstrass::PublicKey<NistP384>;
