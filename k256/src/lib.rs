//! secp256k1 elliptic curve
//!
//! ## Minimum Supported Rust Version
//!
//! Rust **1.37** or higher.
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

/// secp256k1 elliptic curve.
///
/// Specified in Certicom's SECG in SEC 2: Recommended Elliptic Curve Domain Parameters:
///
/// <https://www.secg.org/sec2-v2.pdf>
///
/// The curve's equation is `y² = x³ + 7` over a ~256-bit prime field.
///
/// It's primarily notable for its use in Bitcoin and other cryptocurrencies.
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Secp256k1;

impl Curve for Secp256k1 {
    /// 256-bit (32-byte) private scalar
    type ScalarSize = U32;
}

/// secp256k1 secret keys
pub type SecretKey = elliptic_curve::SecretKey<<Secp256k1 as Curve>::ScalarSize>;

/// secp256k1 public keys
pub type PublicKey = elliptic_curve::weierstrass::PublicKey<Secp256k1>;
