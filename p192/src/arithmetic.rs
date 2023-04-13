//! Pure Rust implementation of group operations on secp192r1.
//!
//! Curve parameters can be found in [FIPS 186-4] § D.1.2.1: Curve P-192.
//!
//! [FIPS 186-4]: https://csrc.nist.gov/publications/detail/fips/186/4/final

pub(crate) mod field;
pub(crate) mod scalar;

use self::{field::FieldElement, scalar::Scalar};
use crate::NistP192;
use elliptic_curve::{CurveArithmetic, PrimeCurveArithmetic};
use primeorder::{point_arithmetic, PrimeCurveParams};

/// Elliptic curve point in affine coordinates.
pub type AffinePoint = primeorder::AffinePoint<NistP192>;

/// Elliptic curve point in projective coordinates.
pub type ProjectivePoint = primeorder::ProjectivePoint<NistP192>;

impl CurveArithmetic for NistP192 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = ProjectivePoint;
    type Scalar = Scalar;
}

impl PrimeCurveArithmetic for NistP192 {
    type CurveGroup = ProjectivePoint;
}

/// Adapted from [FIPS 186-4] § D.1.2.1: Curve P-192.
///
/// [FIPS 186-4]: https://csrc.nist.gov/publications/detail/fips/186/4/final
impl PrimeCurveParams for NistP192 {
    type FieldElement = FieldElement;
    type PointArithmetic = point_arithmetic::EquationAIsMinusThree;

    /// a = -3 (=0xffffffff ffffffff ffffffff fffffffe ffffffff ffffffff fffffffe)
    const EQUATION_A: FieldElement = FieldElement::from_u64(3).neg();

    /// b = 0x64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1
    const EQUATION_B: FieldElement =
        FieldElement::from_hex("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1");

    /// Base point of P-192.
    ///
    /// ```text
    /// Gₓ = 0x188da80e b03090f6 7cbf20eb 43a18800 f4ff0afd 82ff1012
    /// Gᵧ = 0x07192b95 ffc8da78 631011ed 6b24cdd5 73f977a1 1e794811
    /// ```
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_hex("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"),
        FieldElement::from_hex("07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),
    );
}
