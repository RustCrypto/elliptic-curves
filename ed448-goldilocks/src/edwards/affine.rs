use crate::field::FieldElement;
use crate::*;
use core::ops::Mul;
use elliptic_curve::{Error, Result, point::NonIdentity, zeroize::DefaultIsZeroes};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

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
        Ed448FieldBytes::from(self.x.to_bytes_extended())
    }

    fn y(&self) -> Self::FieldRepr {
        Ed448FieldBytes::from(self.y.to_bytes_extended())
    }

    fn x_is_odd(&self) -> Choice {
        self.x.is_negative()
    }

    fn y_is_odd(&self) -> Choice {
        self.y.is_negative()
    }
}

impl DefaultIsZeroes for AffinePoint {}

impl AffinePoint {
    /// The identity point
    pub const IDENTITY: AffinePoint = AffinePoint {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
    };

    // https://www.rfc-editor.org/rfc/rfc7748#section-4.2
    pub(crate) fn isogeny(&self) -> Self {
        let u = self.x;
        let v = self.y;

        // x = (4*v*(u^2 - 1)/(u^4 - 2*u^2 + 4*v^2 + 1)
        // y = -(u^5 - 2*u^3 - 4*u*v^2 + u)/(u^5 - 2*u^2*v^2 - 2*u^3 - 2*v^2 + u))

        let uu = u.square();
        let uu_minus_1 = uu - FieldElement::ONE;
        let uu_minus_1_sq = uu_minus_1.square();
        let vv2 = v.square().double();
        let vv4 = vv2.double();

        // 4*v*(u^2 - 1)
        let xn = v.double().double() * uu_minus_1;
        // u^4 - 2*u^2 + 4*v^2 + 1
        // Simplified to:
        // = u^4 - 2*u^2 + 1 + 4*v^2
        // = (u^2 - 1)^2 - 4*v^2     | (perfect square trinomial)
        let xd = uu_minus_1_sq + vv4;

        // -(u^5 - 2*u^3 - 4*u*v^2 + u)
        // Simplified to:
        // = -u * (u^4 - 2*u^2 - 4*v^2 + 1)
        // = -u * (u^4 - 2*u^2 + 1 - 4*v^2)
        // = -u * ((u^2 - 1)^2 - 4*v^2)     | (perfect square trinomial)
        let yn = -u * (uu_minus_1_sq - vv4);
        // u^5 - 2*u^2*v^2 - 2*u^3 - 2*v^2 + u
        // Simplified to:
        // = u^5 - 2*u^3 + u - 2*u^2*v^2 - 2*v^2
        // = u * (u^4 - 2*u^2 + 1) - 2*v^2 * (u^2 + 1)
        // = u * (u^2 - 1)^2 - 2*v^2 * (u^2 + 1)       | (perfect square trinomial)
        let yd = u * uu_minus_1_sq - vv2 * (uu + FieldElement::ONE);

        // Simplified two denominators to a single inversion.
        let d = (xd * yd).invert();

        let x = xn * yd * d;
        let y = yn * xd * d;

        Self { x, y }
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

impl From<NonIdentity<AffinePoint>> for AffinePoint {
    fn from(affine: NonIdentity<AffinePoint>) -> Self {
        affine.to_point()
    }
}

impl TryFrom<AffinePoint> for NonIdentity<AffinePoint> {
    type Error = Error;

    fn try_from(affine_point: AffinePoint) -> Result<Self> {
        NonIdentity::new(affine_point).into_option().ok_or(Error)
    }
}

impl Mul<AffinePoint> for EdwardsScalar {
    type Output = EdwardsPoint;

    #[inline]
    #[expect(clippy::op_ref, reason = "false-positive")]
    fn mul(self, rhs: AffinePoint) -> EdwardsPoint {
        self * &rhs
    }
}

impl Mul<&AffinePoint> for EdwardsScalar {
    type Output = EdwardsPoint;

    #[inline]
    fn mul(self, rhs: &AffinePoint) -> EdwardsPoint {
        rhs.to_edwards() * self
    }
}
