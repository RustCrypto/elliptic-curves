use crate::curve::twedwards::affine::AffinePoint as InnerAffinePoint;
use crate::field::FieldElement;
use crate::{Decaf448FieldBytes, DecafPoint, Scalar};
use core::ops::Mul;
use elliptic_curve::{Error, point::NonIdentity};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "zeroize")]
use zeroize::DefaultIsZeroes;

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

impl elliptic_curve::point::AffineCoordinates for AffinePoint {
    type FieldRepr = Decaf448FieldBytes;

    fn x(&self) -> Self::FieldRepr {
        Decaf448FieldBytes::from(self.x())
    }

    fn y_is_odd(&self) -> Choice {
        self.0.y.is_negative()
    }
}

#[cfg(feature = "zeroize")]
impl DefaultIsZeroes for AffinePoint {}

impl AffinePoint {
    /// The identity point
    pub const IDENTITY: Self = Self(InnerAffinePoint::IDENTITY);

    /// Convert to DecafPoint
    pub fn to_decaf(&self) -> DecafPoint {
        DecafPoint(self.0.to_extended())
    }

    /// The X coordinate
    pub fn x(&self) -> [u8; 57] {
        // TODO: fix this to be 56 bytes as per
        // https://datatracker.ietf.org/doc/draft-irtf-cfrg-ristretto255-decaf448
        // This might require creating a separate DecafScalar
        self.0.x.to_bytes_extended()
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

impl Mul<Scalar> for AffinePoint {
    type Output = DecafPoint;

    #[inline]
    fn mul(self, scalar: Scalar) -> DecafPoint {
        &self * scalar
    }
}

#[allow(clippy::op_ref)] // https://github.com/rust-lang/rust-clippy/issues/12463
impl Mul<Scalar> for &AffinePoint {
    type Output = DecafPoint;

    #[inline]
    fn mul(self, scalar: Scalar) -> DecafPoint {
        self * &scalar
    }
}

#[allow(clippy::op_ref)] // https://github.com/rust-lang/rust-clippy/issues/12463
impl Mul<&Scalar> for AffinePoint {
    type Output = DecafPoint;

    #[inline]
    fn mul(self, scalar: &Scalar) -> DecafPoint {
        &self * scalar
    }
}

impl Mul<&Scalar> for &AffinePoint {
    type Output = DecafPoint;

    #[inline]
    fn mul(self, scalar: &Scalar) -> DecafPoint {
        self.to_decaf() * scalar
    }
}

impl Mul<AffinePoint> for Scalar {
    type Output = DecafPoint;

    #[inline]
    fn mul(self, point: AffinePoint) -> DecafPoint {
        point * self
    }
}

impl Mul<&AffinePoint> for Scalar {
    type Output = DecafPoint;

    #[inline]
    fn mul(self, point: &AffinePoint) -> DecafPoint {
        point * self
    }
}
