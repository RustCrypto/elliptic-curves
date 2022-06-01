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
use crate::U384;

/// a = -3 (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc)
///
/// NOTE: field element has been translated into the Montgomery domain.
const CURVE_EQUATION_A: FieldElement = FieldElement(U384::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffc0000000000000003fffffffc"));

/// b = b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112
///     0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef
///
/// NOTE: field element has been translated into the Montgomery domain.
const CURVE_EQUATION_B: FieldElement = FieldElement(U384::from_be_hex("cd08114b604fbff9b62b21f41f022094e3374bee94938ae277f2209b1920022ef729add87a4c32ec081188719d412dcc"));
