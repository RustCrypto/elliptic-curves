//! brainpoolP512r1 curve arithmetic implementation.

use super::BrainpoolP512r1;
use crate::{FieldElement, Scalar};
use elliptic_curve::{CurveArithmetic, PrimeCurveArithmetic, hazmat::FieldArithmetic};
use primeorder::{PrimeCurveParams, mul_backend, point_arithmetic};

/// Elliptic curve point in affine coordinates.
pub type AffinePoint = primeorder::AffinePoint<BrainpoolP512r1>;

/// Elliptic curve point in projective coordinates.
pub type ProjectivePoint = primeorder::ProjectivePoint<BrainpoolP512r1>;

/// Primitive scalar type.
pub type ScalarValue = elliptic_curve::ScalarValue<BrainpoolP512r1>;

/// Non-zero scalar field element.
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<BrainpoolP512r1>;

impl CurveArithmetic for BrainpoolP512r1 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = ProjectivePoint;
    type Scalar = Scalar;
}

impl FieldArithmetic for BrainpoolP512r1 {
    type FieldElement = FieldElement;
}

impl PrimeCurveArithmetic for BrainpoolP512r1 {
    type CurveGroup = ProjectivePoint;
}

impl PrimeCurveParams for BrainpoolP512r1 {
    type PointArithmetic = point_arithmetic::EquationAIsGeneric;
    type Backend = mul_backend::VariableOnly;

    const EQUATION_A: FieldElement = FieldElement::from_hex_vartime(
        "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
    );
    const EQUATION_B: FieldElement = FieldElement::from_hex_vartime(
        "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
    );
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_hex_vartime(
            "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
        ),
        FieldElement::from_hex_vartime(
            "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
        ),
    );
}
