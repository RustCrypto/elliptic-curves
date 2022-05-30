//! Pure Rust implementation of group operations on secp384r1.
//!
//! Curve parameters can be found in FIPS 186-4: Digital Signature Standard
//! (DSS): <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//!
//! See section D.1.2.4: Curve P-384.

#![allow(clippy::unusual_byte_groupings)]
pub(crate) mod affine;
pub(crate) mod field;
pub(crate) mod projective;
pub(crate) mod scalar;

use self::{affine::AffinePoint, field::FieldElement, projective::ProjectivePoint, scalar::Scalar};
use elliptic_curve::bigint;

/// Number of limbs used to represent a field element.
const LIMBS: usize = bigint::nlimbs!(384);

/// a = -3 (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc)
/// NOTE: field element has been translated into the Montgomery domain.
#[cfg(target_pointer_width = "32")]
const CURVE_EQUATION_A: FieldElement = FieldElement([
    0xfffffffc, 0x00000003, 0x00000000, 0xfffffffc, 0xfffffffb, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
]);

/// a = -3 (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc)
/// NOTE: field element has been translated into the Montgomery domain.
#[cfg(target_pointer_width = "64")]
const CURVE_EQUATION_A: FieldElement = FieldElement([
    0x00000003_fffffffc,
    0xfffffffc_00000000,
    0xffffffff_fffffffb,
    0xffffffff_ffffffff,
    0xffffffff_ffffffff,
    0xffffffff_ffffffff,
]);

/// b = b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112
///     0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef
///
/// NOTE: field element has been translated into the Montgomery domain.
#[cfg(target_pointer_width = "32")]
const CURVE_EQUATION_B: FieldElement = FieldElement([
    0x9d412dcc, 0x08118871, 0x7a4c32ec, 0xf729add8, 0x1920022e, 0x77f2209b, 0x94938ae2, 0xe3374bee,
    0x1f022094, 0xb62b21f4, 0x604fbff9, 0xcd08114b,
]);

/// b = b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112
///     0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef
///
/// NOTE: field element has been translated into the Montgomery domain.
#[cfg(target_pointer_width = "64")]
const CURVE_EQUATION_B: FieldElement = FieldElement([
    0x08118871_9d412dcc,
    0xf729add8_7a4c32ec,
    0x77f2209b_1920022e,
    0xe3374bee_94938ae2,
    0xb62b21f4_1f022094,
    0xcd08114b_604fbff9,
]);
