//! brainpoolP384r1 curve arithmetic implementation.

use super::BrainpoolP384r1;
use crate::{FieldElement, Scalar};
use elliptic_curve::{CurveArithmetic, PrimeCurveArithmetic};
use primeorder::{point_arithmetic, PrimeCurveParams};

/// Elliptic curve point in affine coordinates.
pub type AffinePoint = primeorder::AffinePoint<BrainpoolP384r1>;

/// Elliptic curve point in projective coordinates.
pub type ProjectivePoint = primeorder::ProjectivePoint<BrainpoolP384r1>;

/// Primitive scalar type.
pub type ScalarPrimitive = elliptic_curve::ScalarPrimitive<BrainpoolP384r1>;

impl CurveArithmetic for BrainpoolP384r1 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = ProjectivePoint;
    type Scalar = Scalar;
}

impl PrimeCurveArithmetic for BrainpoolP384r1 {
    type CurveGroup = ProjectivePoint;
}

impl PrimeCurveParams for BrainpoolP384r1 {
    type FieldElement = FieldElement;
    type PointArithmetic = point_arithmetic::EquationAIsGeneric;

    const EQUATION_A: FieldElement =
        FieldElement::from_hex("7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826");
    const EQUATION_B: FieldElement =
        FieldElement::from_hex("04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11");
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_hex("1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e"),
        FieldElement::from_hex("8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315"),
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
