use crate::curve::edwards::EdwardsPoint;
use crate::field::FieldElement;
use crate::*;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "zeroize")]
use zeroize::DefaultIsZeroes;

/// Affine point on untwisted curve
#[derive(Copy, Clone, Debug)]
pub struct AffinePoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
}

impl Default for AffinePoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
        }
    }
}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AffinePoint {}

impl elliptic_curve::point::AffineCoordinates for AffinePoint {
    type FieldRepr = Ed448FieldBytes;

    fn x(&self) -> Self::FieldRepr {
        Ed448FieldBytes::clone_from_slice(&self.x.to_bytes())
    }

    fn y_is_odd(&self) -> Choice {
        self.y.is_negative()
    }
}

#[cfg(feature = "zeroize")]
impl DefaultIsZeroes for AffinePoint {}

impl AffinePoint {
    /// The identity point
    pub const IDENTITY: AffinePoint = AffinePoint {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
    };

    pub(crate) fn isogeny(&self) -> Self {
        let x = self.x;
        let y = self.y;
        let mut t0 = x.square(); // x^2
        let t1 = t0 + FieldElement::ONE; // x^2+1
        t0 -= FieldElement::ONE; // x^2-1
        let mut t2 = y.square(); // y^2
        t2 = t2.double(); // 2y^2
        let t3 = x.double(); // 2x

        let mut t4 = t0 * y; // y(x^2-1)
        t4 = t4.double(); // 2y(x^2-1)
        let xNum = t4.double(); // xNum = 4y(x^2-1)

        let mut t5 = t0.square(); // x^4-2x^2+1
        t4 = t5 + t2; // x^4-2x^2+1+2y^2
        let xDen = t4 + t2; // xDen = x^4-2x^2+1+4y^2

        t5 *= x; // x^5-2x^3+x
        t4 = t2 * t3; // 4xy^2
        let yNum = t4 - t5; // yNum = -(x^5-2x^3+x-4xy^2)

        t4 = t1 * t2; // 2x^2y^2+2y^2
        let yDen = t5 - t4; // yDen = x^5-2x^3+x-2x^2y^2-2y^2

        Self {
            x: xNum * xDen.invert(),
            y: yNum * yDen.invert(),
        }
    }

    /// Convert to edwards extended point
    pub fn to_edwards(&self) -> EdwardsPoint {
        EdwardsPoint {
            X: self.x,
            Y: self.y,
            Z: FieldElement::ONE,
            T: self.x * self.y,
        }
    }

    /// The X coordinate
    pub fn x(&self) -> [u8; 56] {
        self.x.to_bytes()
    }

    /// The Y coordinate
    pub fn y(&self) -> [u8; 56] {
        self.y.to_bytes()
    }
}
