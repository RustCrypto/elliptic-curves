//! brainpoolP256r1 elliptic curve: verifiably pseudo-random variant

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
    bigint::{ArrayEncoding, U256},
    consts::U32,
    FieldBytesEncoding,
};

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
    const ORDER: U256 = ORDER;
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

/// brainpoolP256r1 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<BrainpoolP256r1>;

/// brainpoolP256r1 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<BrainpoolP256r1>;

impl FieldBytesEncoding<BrainpoolP256r1> for U256 {
    fn decode_field_bytes(field_bytes: &FieldBytes) -> Self {
        U256::from_be_byte_array(*field_bytes)
    }

    fn encode_field_bytes(&self) -> FieldBytes {
        self.to_be_byte_array()
    }
}

/// brainpoolP256r1 secret key.
pub type SecretKey = elliptic_curve::SecretKey<BrainpoolP256r1>;

#[cfg(not(feature = "wip-arithmetic-do-not-use"))]
impl elliptic_curve::sec1::ValidatePublicKey for BrainpoolP256r1 {}
