//! brainpoolP384t1 elliptic curve: twisted variant

#[cfg(feature = "ecdsa")]
pub mod ecdsa;

#[cfg(feature = "wip-arithmetic-do-not-use")]
mod arithmetic;

#[cfg(feature = "wip-arithmetic-do-not-use")]
pub use {
    self::arithmetic::{AffinePoint, ProjectivePoint},
    crate::Scalar,
};

use crate::ORDER;
use elliptic_curve::{
    bigint::{ArrayEncoding, U384},
    consts::U48,
    FieldBytesEncoding,
};

#[cfg(feature = "pkcs8")]
use crate::pkcs8;

/// brainpoolP384t1 elliptic curve: twisted variant
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BrainpoolP384t1;

impl elliptic_curve::Curve for BrainpoolP384t1 {
    /// 48-byte serialized field elements.
    type FieldBytesSize = U48;

    /// 384-bit field modulus.
    type Uint = U384;

    /// Curve order.
    const ORDER: U384 = ORDER;
}

impl elliptic_curve::PrimeCurve for BrainpoolP384t1 {}

impl elliptic_curve::point::PointCompression for BrainpoolP384t1 {
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl pkcs8::AssociatedOid for BrainpoolP384t1 {
    const OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.12");
}

/// brainpoolP384t1 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<BrainpoolP384t1>;

/// brainpoolP384t1 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<BrainpoolP384t1>;

impl FieldBytesEncoding<BrainpoolP384t1> for U384 {
    fn decode_field_bytes(field_bytes: &FieldBytes) -> Self {
        U384::from_be_byte_array(*field_bytes)
    }

    fn encode_field_bytes(&self) -> FieldBytes {
        self.to_be_byte_array()
    }
}

/// brainpoolP384t1 secret key.
pub type SecretKey = elliptic_curve::SecretKey<BrainpoolP384t1>;

#[cfg(not(feature = "wip-arithmetic-do-not-use"))]
impl elliptic_curve::sec1::ValidatePublicKey for BrainpoolP384t1 {}
