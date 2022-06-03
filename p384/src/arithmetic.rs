//! Pure Rust implementation of group operations on secp384r1.
//!
//! Curve parameters can be found in FIPS 186-4: Digital Signature Standard
//! (DSS): <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//!
//! See section D.1.2.4: Curve P-384.

#[macro_use]
mod macros;

pub(crate) mod affine;
pub(crate) mod field;
pub(crate) mod projective;
pub(crate) mod scalar;

use self::{
    affine::AffinePoint,
    field::{FieldElement, MODULUS},
    projective::ProjectivePoint,
    scalar::Scalar,
};

/// a = -3 (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc)
const CURVE_EQUATION_A: FieldElement = FieldElement::ZERO
    .sub(&FieldElement::ONE)
    .sub(&FieldElement::ONE)
    .sub(&FieldElement::ONE);

/// b = b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112
///     0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef
const CURVE_EQUATION_B: FieldElement =
    FieldElement::from_be_hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef");
