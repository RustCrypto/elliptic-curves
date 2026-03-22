//! Pure Rust implementation of group operations on bign-curve256v1.
//!
//! Curve parameters can be found in STB 34.101.45-2013
//! <https://apmi.bsu.by/assets/files/std/bign-spec294.pdf>
//!
//! See table B.1: l = 128.

pub(crate) mod field;
pub(crate) mod scalar;

pub use self::scalar::Scalar;

pub use self::field::FieldElement;
use crate::BignP256;
pub use elliptic_curve::{CurveArithmetic, PrimeCurveArithmetic};
pub use primeorder::{PrimeCurveParams, point_arithmetic};

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
    const EQUATION_A: Self::FieldElement = FieldElement::from_hex_vartime(
        "40FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    );
    const EQUATION_B: Self::FieldElement = FieldElement::from_hex_vartime(
        "F1039CD66B7D2EB253928B976950F54CBEFBD8E4AB3AC1D2EDA8F315156CCE77",
    );
    const GENERATOR: (Self::FieldElement, Self::FieldElement) = (
        FieldElement::ZERO,
        FieldElement::from_hex_vartime(
            "936A510418CF291E52F608C4663991785D83D651A3C9E45C9FD616FB3CFCF76B",
        ),
    );
}
