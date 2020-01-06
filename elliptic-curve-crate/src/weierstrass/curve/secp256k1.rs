//! secp256k1 elliptic curve

use super::Curve;
use generic_array::typenum::U32;

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
pub type SecretKey = crate::weierstrass::SecretKey<Secp256k1>;

/// secp256k1 public keys
pub type PublicKey = crate::weierstrass::PublicKey<Secp256k1>;
