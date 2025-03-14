use crate::curve::twedwards::affine::AffinePoint as InnerAffinePoint;
use crate::field::FieldElement;
use crate::{Decaf448FieldBytes, DecafPoint};
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
        Decaf448FieldBytes::clone_from_slice(&self.x())
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
    pub fn x(&self) -> [u8; 56] {
        self.0.x.to_bytes()
    }

    /// The Y coordinate
    pub fn y(&self) -> [u8; 56] {
        self.0.y.to_bytes()
    }
}
