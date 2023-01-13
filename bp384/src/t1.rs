//! brainpoolP384t1 elliptic curve: twisted variant

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

use elliptic_curve::bigint::U384;

#[cfg(feature = "pkcs8")]
use crate::pkcs8;

/// brainpoolP384t1 elliptic curve: twisted variant
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BrainpoolP384t1;

impl elliptic_curve::Curve for BrainpoolP384t1 {
    /// 384-bit field modulus
    type UInt = U384;

    /// Curve order
    const ORDER: U384 =
        U384::from_be_hex("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565");
}

impl elliptic_curve::PrimeCurve for BrainpoolP384t1 {}

impl elliptic_curve::PointCompression for BrainpoolP384t1 {
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for BrainpoolP384t1 {
    const OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.12");
}

/// brainpoolP384t1 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<BrainpoolP384t1>;

/// brainpoolP384t1 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<BrainpoolP384t1>;

/// brainpoolP384t1 secret key.
pub type SecretKey = elliptic_curve::SecretKey<BrainpoolP384t1>;

impl elliptic_curve::sec1::ValidatePublicKey for BrainpoolP384t1 {}
