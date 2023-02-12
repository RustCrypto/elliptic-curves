//! Pure Rust implementation of group operations on secp224r1.
//!
//! Curve parameters can be found in [NIST SP 800-186] § 3.2.1.2: P-224.
//!
//! [NIST SP 800-186]: https://csrc.nist.gov/publications/detail/sp/800-186/final

pub(crate) mod field;
pub(crate) mod scalar;

pub use self::scalar::Scalar;

use self::field::FieldElement;
use crate::NistP224;
use elliptic_curve::{CurveArithmetic, PrimeCurveArithmetic};
use primeorder::{point_arithmetic, PrimeCurveParams};

/// Elliptic curve point in affine coordinates.
pub type AffinePoint = primeorder::AffinePoint<NistP224>;

/// Elliptic curve point in projective coordinates.
pub type ProjectivePoint = primeorder::ProjectivePoint<NistP224>;

impl CurveArithmetic for NistP224 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = ProjectivePoint;
    type Scalar = Scalar;
}

impl PrimeCurveArithmetic for NistP224 {
    type CurveGroup = ProjectivePoint;
}

/// Adapted from [NIST SP 800-186] § 3.2.1.2: P-224.
///
/// [NIST SP 800-186]: https://csrc.nist.gov/publications/detail/sp/800-186/final
impl PrimeCurveParams for NistP224 {
    type FieldElement = FieldElement;
    type PointArithmetic = point_arithmetic::EquationAIsMinusThree;

    /// a = -3 (=0xffffffff ffffffff ffffffff fffffffe ffffffff ffffffff fffffffe)
    const EQUATION_A: FieldElement = FieldElement::from_u64(3).neg();

    /// b = 0xb4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4
    #[cfg(target_pointer_width = "32")]
    const EQUATION_B: FieldElement =
        FieldElement::from_hex("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4");

    /// b = 0xb4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4
    #[cfg(target_pointer_width = "64")]
    const EQUATION_B: FieldElement =
        FieldElement::from_hex("00000000b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4");

    /// Base point of P-224.
    ///
    /// ```text
    /// Gₓ = 0xb70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6 115c1d21
    /// Gᵧ = 0xbd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199 85007e34
    /// ```
    #[cfg(target_pointer_width = "32")]
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_hex("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"),
        FieldElement::from_hex("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
    );

    /// Base point of P-224.
    ///
    /// ```text
    /// Gₓ = 0xb70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6 115c1d21
    /// Gᵧ = 0xbd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199 85007e34
    /// ```
    #[cfg(target_pointer_width = "64")]
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_hex("00000000b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"),
        FieldElement::from_hex("00000000bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
    );
}
