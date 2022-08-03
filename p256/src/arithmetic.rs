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
use weierstrass::WeierstrassCurve;

/// Elliptic curve point in affine coordinates.
pub type AffinePoint = weierstrass::AffinePoint<NistP256>;

/// Elliptic curve point in projective coordinates.
pub type ProjectivePoint = weierstrass::ProjectivePoint<NistP256>;

impl WeierstrassCurve for NistP256 {
    type FieldElement = FieldElement;

    const ZERO: FieldElement = FieldElement::ZERO;
    const ONE: FieldElement = FieldElement::ONE;

    /// a = -3
    const EQUATION_A: FieldElement = FieldElement::ZERO
        .sub(&FieldElement::ONE)
        .sub(&FieldElement::ONE)
        .sub(&FieldElement::ONE);

    /// b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    const EQUATION_B: FieldElement = FieldElement([
        0xd89c_df62_29c4_bddf,
        0xacf0_05cd_7884_3090,
        0xe5a2_20ab_f721_2ed6,
        0xdc30_061d_0487_4834,
    ]);

    /// Base point of P-256.
    ///
    /// Defined in FIPS 186-4 § D.1.2.3:
    ///
    /// ```text
    /// Gₓ = 6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296
    /// Gᵧ = 4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5
    /// ```
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement([
            0xf4a1_3945_d898_c296,
            0x7703_7d81_2deb_33a0,
            0xf8bc_e6e5_63a4_40f2,
            0x6b17_d1f2_e12c_4247,
        ])
        .to_montgomery(),
        FieldElement([
            0xcbb6_4068_37bf_51f5,
            0x2bce_3357_6b31_5ece,
            0x8ee7_eb4a_7c0f_9e16,
            0x4fe3_42e2_fe1a_7f9b,
        ])
        .to_montgomery(),
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
