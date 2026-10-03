//! brainpoolP512t1 curve arithmetic implementation.

use super::BrainpoolP512t1;
use crate::{FieldElement, Scalar};
use elliptic_curve::{CurveArithmetic, PrimeCurveArithmetic, hazmat::FieldArithmetic};
use primeorder::{PrimeCurveParams, mul_backend, point_arithmetic};

/// Elliptic curve point in affine coordinates.
pub type AffinePoint = primeorder::AffinePoint<BrainpoolP512t1>;

/// Elliptic curve point in projective coordinates.
pub type ProjectivePoint = primeorder::ProjectivePoint<BrainpoolP512t1>;

/// Primitive scalar type.
pub type ScalarValue = elliptic_curve::ScalarValue<BrainpoolP512t1>;

/// Non-zero scalar field element.
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<BrainpoolP512t1>;

impl CurveArithmetic for BrainpoolP512t1 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = ProjectivePoint;
    type Scalar = Scalar;
}

impl FieldArithmetic for BrainpoolP512t1 {
    type FieldElement = FieldElement;
}

impl PrimeCurveArithmetic for BrainpoolP512t1 {
    type CurveGroup = ProjectivePoint;
}

impl PrimeCurveParams for BrainpoolP512t1 {
    type PointArithmetic = point_arithmetic::EquationAIsMinusThree;
    type Backend = mul_backend::VariableOnly;

    const EQUATION_A: FieldElement = FieldElement::from_u64(3).neg();
    const EQUATION_B: FieldElement = FieldElement::from_hex_vartime(
        "7cbbbcf9441cfab76e1890e46884eae321f70c0bcb4981527897504bec3e36a62bcdfa2304976540f6450085f2dae145c22553b465763689180ea2571867423e",
    );
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_hex_vartime(
            "640ece5c12788717b9c1ba06cbc2a6feba85842458c56dde9db1758d39c0313d82ba51735cdb3ea499aa77a7d6943a64f7a3f25fe26f06b51baa2696fa9035da",
        ),
        FieldElement::from_hex_vartime(
            "5b534bd595f5af0fa2c892376c84ace1bb4e3019b71634c01131159cae03cee9d9932184beef216bd71df2dadf86a627306ecff96dbb8bace198b61e00f8b332",
        ),
    );
}
