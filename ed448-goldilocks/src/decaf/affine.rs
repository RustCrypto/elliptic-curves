use crate::curve::twedwards::affine::AffinePoint as InnerAffinePoint;
use crate::decaf::points::DecafPointRepr;
use crate::field::FieldElement;
use crate::{Decaf448FieldBytes, DecafPoint, DecafScalar, ORDER};
use core::ops::{Mul, Neg};
use elliptic_curve::{
    Error,
    group::{GroupEncoding, prime::PrimeCurveAffine},
    point::{AffineCoordinates, NonIdentity},
    zeroize::DefaultIsZeroes,
};
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Affine point on the twisted curve
#[derive(Copy, Clone, Debug, Default)]
pub struct AffinePoint(pub(crate) InnerAffinePoint);

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.x.ct_eq(&other.0.x) & self.0.y.ct_eq(&other.0.y)
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(InnerAffinePoint {
            x: FieldElement::conditional_select(&a.0.x, &b.0.x, choice),
            y: FieldElement::conditional_select(&a.0.y, &b.0.y, choice),
        })
    }
}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AffinePoint {}

impl AffineCoordinates for AffinePoint {
    type FieldRepr = Decaf448FieldBytes;

    fn from_coordinates(x: &Self::FieldRepr, y: &Self::FieldRepr) -> CtOption<Self> {
        let point = Self(InnerAffinePoint {
            x: FieldElement::from_bytes(&x.0),
            y: FieldElement::from_bytes(&y.0),
        });

        CtOption::new(
            point,
            point.0.is_on_curve() & (point * DecafScalar::new(*ORDER)).ct_eq(&DecafPoint::IDENTITY),
        )
    }

    fn x(&self) -> Self::FieldRepr {
        Decaf448FieldBytes::from(self.x())
    }

    fn y(&self) -> Self::FieldRepr {
        Decaf448FieldBytes::from(self.y())
    }

    fn x_is_odd(&self) -> Choice {
        self.0.x.is_negative()
    }

    fn y_is_odd(&self) -> Choice {
        self.0.y.is_negative()
    }
}

impl DefaultIsZeroes for AffinePoint {}

impl GroupEncoding for AffinePoint {
    type Repr = DecafPointRepr;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        Self::from_bytes_unchecked(bytes)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        let s = FieldElement::from_bytes(&bytes.0);
        //XX: Check for canonical encoding and sign,
        // Copied this check from Dalek: The From_bytes function does not throw an error, if the bytes exceed the prime.
        // However, to_bytes reduces the Field element before serialising
        // So we can use to_bytes -> from_bytes and if the representations are the same, then the element was already in reduced form
        let s_bytes_check = s.to_bytes();
        let s_encoding_is_canonical = s_bytes_check[..].ct_eq(&bytes.0);
        let s_is_negative = s.is_negative();
        // if s_encoding_is_canonical.unwrap_u8() == 0u8 || s.is_negative().unwrap_u8() == 1u8 {
        //     return None;
        // }

        let ss = s.square();
        let u1 = FieldElement::ONE - ss;
        let u2 = FieldElement::ONE + ss;
        let u1_sqr = u1.square();

        let v = ss * (FieldElement::NEG_FOUR_TIMES_TWISTED_D) + u1_sqr; // XXX: constantify please

        let (I, ok) = (v * u1_sqr).inverse_square_root();

        let Dx = I * u1;
        let Dxs = s.double() * Dx;

        let mut x = (Dxs * I) * v;
        let k = Dxs * FieldElement::DECAF_FACTOR;
        x.conditional_negate(k.is_negative());

        let y = Dx * u2;
        let pt = InnerAffinePoint { x, y };

        CtOption::new(
            Self(pt),
            ok & pt.is_on_curve() & s_encoding_is_canonical & !s_is_negative,
        )
    }

    fn to_bytes(&self) -> Self::Repr {
        self.to_decaf().to_bytes()
    }
}

impl PrimeCurveAffine for AffinePoint {
    type Scalar = DecafScalar;
    type Curve = DecafPoint;

    fn identity() -> Self {
        Self::IDENTITY
    }

    fn generator() -> Self {
        Self::GENERATOR
    }

    fn is_identity(&self) -> Choice {
        self.ct_eq(&Self::IDENTITY)
    }

    fn to_curve(&self) -> Self::Curve {
        self.to_decaf()
    }
}

impl AffinePoint {
    /// The identity point
    pub const IDENTITY: Self = Self(InnerAffinePoint::IDENTITY);
    /// The generator point
    pub const GENERATOR: Self = Self(InnerAffinePoint::GENERATOR);

    /// Convert to DecafPoint
    pub fn to_decaf(&self) -> DecafPoint {
        DecafPoint(self.0.to_extended())
    }

    /// The X coordinate
    pub fn x(&self) -> [u8; 56] {
        self.0.x.to_bytes()
    }

    /// The Y coordinate
    pub fn y(&self) -> [u8; 56] {
        self.0.y.to_bytes()
    }
}

/// The constant-time alternative is available at [`NonIdentity::new()`].
impl TryFrom<AffinePoint> for NonIdentity<AffinePoint> {
    type Error = Error;

    fn try_from(affine_point: AffinePoint) -> Result<Self, Error> {
        NonIdentity::new(affine_point).into_option().ok_or(Error)
    }
}

impl From<NonIdentity<AffinePoint>> for AffinePoint {
    fn from(affine: NonIdentity<AffinePoint>) -> Self {
        affine.to_point()
    }
}

impl Mul<&DecafScalar> for &AffinePoint {
    type Output = DecafPoint;

    #[inline]
    fn mul(self, scalar: &DecafScalar) -> DecafPoint {
        self.to_decaf() * scalar
    }
}

define_mul_variants!(LHS = AffinePoint, RHS = DecafScalar, Output = DecafPoint);

impl Neg for AffinePoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.negate())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use elliptic_curve::CurveGroup;

    #[test]
    fn generator() {
        assert_eq!(AffinePoint::GENERATOR.to_decaf(), DecafPoint::GENERATOR);
        assert_eq!(DecafPoint::GENERATOR.to_affine(), AffinePoint::GENERATOR);
    }
}
