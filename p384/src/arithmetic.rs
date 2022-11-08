//! Pure Rust implementation of group operations on secp384r1.
//!
//! Curve parameters can be found in FIPS 186-4: Digital Signature Standard
//! (DSS): <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//!
//! See section D.1.2.4: Curve P-384.

#[macro_use]
mod macros;

pub(crate) mod field;
pub(crate) mod scalar;

use self::{field::FieldElement, scalar::Scalar};
use crate::NistP384;
use elliptic_curve::{
    AffineArithmetic, PrimeCurveArithmetic, ProjectiveArithmetic, ScalarArithmetic,
};
use primeorder::PrimeOrderCurve;

/// Elliptic curve point in affine coordinates.
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub type AffinePoint = primeorder::AffinePoint<NistP384>;

/// Elliptic curve point in projective coordinates.
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub type ProjectivePoint = primeorder::ProjectivePoint<NistP384>;

impl PrimeOrderCurve for NistP384 {
    type FieldElement = FieldElement;

    const ZERO: FieldElement = FieldElement::ZERO;
    const ONE: FieldElement = FieldElement::ONE;

    /// a = -3 (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc)
    const EQUATION_A: FieldElement = FieldElement::ZERO
        .sub(&FieldElement::ONE)
        .sub(&FieldElement::ONE)
        .sub(&FieldElement::ONE);

    /// b = b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112
    ///     0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef
    const EQUATION_B: FieldElement = FieldElement::from_be_hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef");

    /// Base point of P-384.
    ///
    /// Defined in FIPS 186-4 § D.1.2.4:
    ///
    /// ```text
    /// Gₓ = aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98
    ///      59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7
    /// Gᵧ = 3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c
    ///      e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f
    /// ```
    ///
    /// NOTE: coordinate field elements have been translated into the Montgomery
    /// domain.
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_be_hex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
        FieldElement::from_be_hex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
    );
}

impl AffineArithmetic for NistP384 {
    type AffinePoint = AffinePoint;
}

impl ProjectiveArithmetic for NistP384 {
    type ProjectivePoint = ProjectivePoint;
}

impl PrimeCurveArithmetic for NistP384 {
    type CurveGroup = ProjectivePoint;
}

impl ScalarArithmetic for NistP384 {
    type Scalar = Scalar;
}
