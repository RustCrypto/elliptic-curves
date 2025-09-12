//! brainpoolP256t1 elliptic curve: twisted variant

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

#[cfg(feature = "arithmetic")]
mod arithmetic;

#[cfg(feature = "arithmetic")]
pub use {
    self::arithmetic::{AffinePoint, NonZeroScalar, ProjectivePoint, ScalarPrimitive},
    crate::Scalar,
};

use crate::ORDER;
use elliptic_curve::{
    FieldBytesEncoding,
    bigint::{Odd, U256},
    consts::U32,
};

#[cfg(feature = "pkcs8")]
use crate::pkcs8;

/// brainpoolP256t1 elliptic curve: twisted variant
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BrainpoolP256t1;

impl elliptic_curve::Curve for BrainpoolP256t1 {
    /// 32-byte serialized field elements.
    type FieldBytesSize = U32;

    /// 256-bit field modulus.
    type Uint = U256;

    /// Curve order
    const ORDER: Odd<U256> = ORDER;
}

impl elliptic_curve::PrimeCurve for BrainpoolP256t1 {}

impl elliptic_curve::point::PointCompression for BrainpoolP256t1 {
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for BrainpoolP256t1 {
    const OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.8");
}

/// brainpoolP256t1 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<BrainpoolP256t1>;

/// brainpoolP256t1 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<BrainpoolP256t1>;

impl FieldBytesEncoding<BrainpoolP256t1> for U256 {
    fn decode_field_bytes(field_bytes: &crate::r1::FieldBytes) -> Self {
        crate::decode_field_bytes(field_bytes)
    }

    fn encode_field_bytes(&self) -> crate::r1::FieldBytes {
        crate::encode_field_bytes(self)
    }
}

/// brainpoolP256t1 secret key.
pub type SecretKey = elliptic_curve::SecretKey<BrainpoolP256t1>;

#[cfg(not(feature = "arithmetic"))]
impl elliptic_curve::sec1::ValidatePublicKey for BrainpoolP256t1 {}
