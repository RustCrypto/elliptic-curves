//! brainpoolP256r1 elliptic curve: verifiably pseudo-random variant

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

use elliptic_curve::{bigint::U256, consts::U32};

#[cfg(feature = "pkcs8")]
use crate::pkcs8;

/// brainpoolP256r1 elliptic curve: verifiably pseudo-random variant
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BrainpoolP256r1;

impl elliptic_curve::Curve for BrainpoolP256r1 {
    /// 32-byte serialized field elements.
    type FieldBytesSize = U32;

    /// 256-bit field modulus.
    type Uint = U256;

    /// Curve order
    const ORDER: U256 =
        U256::from_be_hex("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7");
}

impl elliptic_curve::PrimeCurve for BrainpoolP256r1 {}

impl elliptic_curve::point::PointCompression for BrainpoolP256r1 {
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for BrainpoolP256r1 {
    const OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7");
}

/// brainpoolP256r1 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<BrainpoolP256r1>;

/// brainpoolP256r1 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<BrainpoolP256r1>;

/// brainpoolP256r1 secret key.
pub type SecretKey = elliptic_curve::SecretKey<BrainpoolP256r1>;

impl elliptic_curve::sec1::ValidatePublicKey for BrainpoolP256r1 {}
