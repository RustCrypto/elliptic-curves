//! brainpoolP384t1 curve arithmetic implementation.

use super::BrainpoolP384t1;
use crate::{FieldElement, Scalar};
use elliptic_curve::{CurveArithmetic, PrimeCurveArithmetic};
use primeorder::{point_arithmetic, PrimeCurveParams};

/// Elliptic curve point in affine coordinates.
pub type AffinePoint = primeorder::AffinePoint<BrainpoolP384t1>;

/// Elliptic curve point in projective coordinates.
pub type ProjectivePoint = primeorder::ProjectivePoint<BrainpoolP384t1>;

/// Primitive scalar type.
pub type ScalarPrimitive = elliptic_curve::ScalarPrimitive<BrainpoolP384t1>;

impl CurveArithmetic for BrainpoolP384t1 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = ProjectivePoint;
    type Scalar = Scalar;
}

impl PrimeCurveArithmetic for BrainpoolP384t1 {
    type CurveGroup = ProjectivePoint;
}

impl PrimeCurveParams for BrainpoolP384t1 {
    type FieldElement = FieldElement;
    type PointArithmetic = point_arithmetic::EquationAIsGeneric;

    const EQUATION_A: FieldElement =
        FieldElement::from_hex("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec50");
    const EQUATION_B: FieldElement =
        FieldElement::from_hex("7f519eada7bda81bd826dba647910f8c4b9346ed8ccdc64e4b1abd11756dce1d2074aa263b88805ced70355a33b471ee");
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_hex("18de98b02db9a306f2afcd7235f72a819b80ab12ebd653172476fecd462aabffc4ff191b946a5f54d8d0aa2f418808cc"),
        FieldElement::from_hex("25ab056962d30651a114afd2755ad336747f93475b7a1fca3b88f2b6a208ccfe469408584dc2b2912675bf5b9e582928"),
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
