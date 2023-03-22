//! Pure Rust implementation of group operations on secp384r1.
//!
//! Curve parameters can be found in FIPS 186-4: Digital Signature Standard
//! (DSS): <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//!
//! See section D.1.2.4: Curve P-384.

pub(crate) mod field;
pub(crate) mod scalar;

pub use self::scalar::Scalar;

use self::field::FieldElement;
use crate::BignP256;
use elliptic_curve::{CurveArithmetic, PrimeCurveArithmetic};
use primeorder::{point_arithmetic, PrimeCurveParams};

/// Elliptic curve point in affine coordinates.
pub type AffinePoint = primeorder::AffinePoint<BignP256>;

/// Elliptic curve point in projective coordinates.
pub type ProjectivePoint = primeorder::ProjectivePoint<BignP256>;

impl CurveArithmetic for BignP256 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = ProjectivePoint;
    type Scalar = Scalar;
}

impl PrimeCurveArithmetic for BignP256 {
    type CurveGroup = ProjectivePoint;
}

impl PrimeCurveParams for BignP256 {
    type FieldElement = FieldElement;
    type PointArithmetic = point_arithmetic::EquationAIsGeneric;
    const EQUATION_A: Self::FieldElement =
        FieldElement::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40");
    const EQUATION_B: Self::FieldElement =
        FieldElement::from_hex("77CE6C1515F3A8EDD2C13AABE4D8FBBE4CF55069978B9253B22E7D6BD69C03F1");
    const GENERATOR: (Self::FieldElement, Self::FieldElement) = (
        FieldElement::ZERO,
        FieldElement::from_hex("6BF7FC3CFB16D69F5CE4C9A351D6835D78913966C408F6521E29CF1804516A93"),
    );
}
