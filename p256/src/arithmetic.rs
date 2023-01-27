//! Pure Rust implementation of group operations on secp256r1.

pub(crate) mod field;
#[cfg(feature = "hash2curve")]
mod hash2curve;
pub(crate) mod scalar;
pub(crate) mod util;

use self::{field::FieldElement, scalar::Scalar};
use crate::NistP256;
use elliptic_curve::{
    AffineArithmetic, PrimeCurveArithmetic, ProjectiveArithmetic, ScalarArithmetic,
};
use primeorder::{CurveEquationAIsMinusThree, PrimeCurveParams};

/// Elliptic curve point in affine coordinates.
pub type AffinePoint = primeorder::AffinePoint<NistP256>;

/// Elliptic curve point in projective coordinates.
pub type ProjectivePoint = primeorder::ProjectivePoint<NistP256>;

impl PrimeCurveParams for NistP256 {
    type FieldElement = FieldElement;
    type CurveEquationAProperties = CurveEquationAIsMinusThree;

    const ZERO: FieldElement = FieldElement::ZERO;
    const ONE: FieldElement = FieldElement::ONE;

    /// a = -3
    const EQUATION_A: FieldElement = FieldElement::ZERO
        .sub(&FieldElement::ONE)
        .sub(&FieldElement::ONE)
        .sub(&FieldElement::ONE);

    const EQUATION_B: FieldElement = FieldElement::from_be_hex(
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    );

    /// Base point of P-256.
    ///
    /// Defined in FIPS 186-4 § D.1.2.3:
    ///
    /// ```text
    /// Gₓ = 6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296
    /// Gᵧ = 4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5
    /// ```
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_be_hex(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        ),
        FieldElement::from_be_hex(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        ),
    );
}

impl AffineArithmetic for NistP256 {
    type AffinePoint = AffinePoint;
}

impl ProjectiveArithmetic for NistP256 {
    type ProjectivePoint = ProjectivePoint;
}

impl PrimeCurveArithmetic for NistP256 {
    type CurveGroup = ProjectivePoint;
}

impl ScalarArithmetic for NistP256 {
    type Scalar = Scalar;
}
