use ecdsa_core::RecoveryId;
pub use ecdsa_core::signature::{self, Error};
use elliptic_curve::ops::{Invert, MulByGenerator, Reduce};
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::scalar::IsHigh;
use elliptic_curve::subtle::CtOption;

use super::BignP256;

#[cfg(feature = "ecdsa")]
use {
    crate::{AffinePoint, Scalar},
    ecdsa_core::hazmat::{SignPrimitive, VerifyPrimitive},
};
use crate::ecdsa::signature::digest::consts::U256;
use crate::{FieldBytes, ProjectivePoint, Uint};

/// ECDSA/P-256 signature (fixed-size)
pub type Signature = ecdsa_core::Signature<BignP256>;

/// ECDSA/P-256 signature (ASN.1 DER encoded)
pub type DerSignature = ecdsa_core::der::Signature<BignP256>;

/// ECDSA/P-256 signing key
#[cfg(feature = "ecdsa")]
pub type SigningKey = ecdsa_core::SigningKey<BignP256>;

/// ECDSA/P-256 verification key (i.e. public key)
#[cfg(feature = "ecdsa")]
pub type VerifyingKey = ecdsa_core::VerifyingKey<BignP256>;

#[cfg(feature = "belt-hash")]
impl ecdsa_core::hazmat::DigestPrimitive for BignP256 {
    type Digest = belt_hash::BeltHash;
}

#[cfg(feature = "ecdsa")]
impl SignPrimitive<BignP256> for Scalar {}

#[cfg(feature = "ecdsa")]
impl VerifyPrimitive<BignP256> for AffinePoint {}
