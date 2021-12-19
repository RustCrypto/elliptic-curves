//! Pure Rust implementation of group operations on secp384r1.
//!
//! Curve parameters can be found in FIPS 186-4: Digital Signature Standard (DSS):
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//!
//! See section D.1.2.4: Curve P-384.

#![allow(clippy::unusual_byte_groupings)]

pub(crate) mod affine;
mod field;
pub(crate) mod scalar;

use field::{FieldElement, MODULUS};

/// a = -3
const CURVE_EQUATION_A: FieldElement = FieldElement([
    MODULUS.0[0] - 3,
    MODULUS.0[1],
    MODULUS.0[2],
    MODULUS.0[3],
    MODULUS.0[4],
    MODULUS.0[5],
]);

/// b = b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112
///     0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef
const CURVE_EQUATION_B: FieldElement = FieldElement([
    0x2a85c8ed_d3ec2aef,
    0xc656398d_8a2ed19d,
    0x0314088f_5013875a,
    0x181d9c6e_fe814112,
    0x988e056b_e3f82d19,
    0xb3312fa7_e23ee7e4,
]);
