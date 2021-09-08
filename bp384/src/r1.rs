//! brainpoolP384r1 elliptic curve: verifiably pseudo-random variant

#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub mod ecdsa;

use elliptic_curve::bigint::U384;

#[cfg(feature = "pkcs8")]
use crate::pkcs8;

/// brainpoolP384r1 elliptic curve: verifiably pseudo-random variant
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BrainpoolP384r1;

impl elliptic_curve::Curve for BrainpoolP384r1 {
    /// 384-bit field modulus
    type UInt = U384;

    /// Curve order
    const ORDER: U384 =
        U384::from_be_hex("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565");
}

impl elliptic_curve::PrimeCurve for BrainpoolP384r1 {}

impl elliptic_curve::PointCompression for BrainpoolP384r1 {
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl elliptic_curve::AlgorithmParameters for BrainpoolP384r1 {
    const OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new("1.3.36.3.3.2.8.1.1.11");
}

/// brainpoolP384r1 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<BrainpoolP384r1>;

/// brainpoolP384r1 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<BrainpoolP384r1>;

/// brainpoolP384r1 secret key.
pub type SecretKey = elliptic_curve::SecretKey<BrainpoolP384r1>;

impl elliptic_curve::sec1::ValidatePublicKey for BrainpoolP384r1 {}
