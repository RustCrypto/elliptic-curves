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

use affine::AffinePoint;
use field::{FieldElement, MODULUS};
use projective::ProjectivePoint;
use scalar::Scalar;

/// a = -3 (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc)
/// NOTE: field element has been translated into the Montgomery domain.
const CURVE_EQUATION_A: FieldElement = FieldElement([
    17179869180,
    18446744056529682432,
    18446744073709551611,
    18446744073709551615,
    18446744073709551615,
    18446744073709551615,
]);

/// b = b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112
///     0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef
///
/// NOTE: field element has been translated into the Montgomery domain.
const CURVE_EQUATION_B: FieldElement = FieldElement([
    0x81188719_d412dcc,
    0xf729add8_7a4c32ec,
    0x77f2209b_1920022e,
    0xe3374bee_94938ae2,
    0xb62b21f4_1f022094,
    0xcd08114b_604fbff9,
]);
