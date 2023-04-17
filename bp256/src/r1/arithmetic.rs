//! brainpoolP256r1 curve arithmetic implementation.

use super::BrainpoolP256r1;
use crate::{FieldElement, Scalar};
use elliptic_curve::{CurveArithmetic, PrimeCurveArithmetic};
use primeorder::{point_arithmetic, PrimeCurveParams};

/// Elliptic curve point in affine coordinates.
pub type AffinePoint = primeorder::AffinePoint<BrainpoolP256r1>;

/// Elliptic curve point in projective coordinates.
pub type ProjectivePoint = primeorder::ProjectivePoint<BrainpoolP256r1>;

/// Primitive scalar type.
pub type ScalarPrimitive = elliptic_curve::ScalarPrimitive<BrainpoolP256r1>;

impl CurveArithmetic for BrainpoolP256r1 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = ProjectivePoint;
    type Scalar = Scalar;
}

impl PrimeCurveArithmetic for BrainpoolP256r1 {
    type CurveGroup = ProjectivePoint;
}

impl PrimeCurveParams for BrainpoolP256r1 {
    type FieldElement = FieldElement;
    type PointArithmetic = point_arithmetic::EquationAIsGeneric;

    const EQUATION_A: FieldElement =
        FieldElement::from_hex("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9");
    const EQUATION_B: FieldElement =
        FieldElement::from_hex("26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6");
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_hex("8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262"),
        FieldElement::from_hex("547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997"),
    );
}

impl From<ScalarPrimitive> for Scalar {
    fn from(w: ScalarPrimitive) -> Self {
        Scalar::from(&w)
    }
}

impl From<&ScalarPrimitive> for Scalar {
    fn from(w: &ScalarPrimitive) -> Scalar {
        Scalar::from_uint_unchecked(*w.as_uint())
    }
}

impl From<Scalar> for ScalarPrimitive {
    fn from(scalar: Scalar) -> ScalarPrimitive {
        ScalarPrimitive::from(&scalar)
    }
}

impl From<&Scalar> for ScalarPrimitive {
    fn from(scalar: &Scalar) -> ScalarPrimitive {
        ScalarPrimitive::new(scalar.into()).unwrap()
    }
}
