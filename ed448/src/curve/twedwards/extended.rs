#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::curve::edwards::EdwardsPoint as EdwardsExtendedPoint;
use crate::curve::twedwards::affine::AffinePoint;
use crate::curve::twedwards::extensible::ExtensiblePoint;
use crate::field::FieldElement;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[derive(Copy, Clone, Debug)]
pub struct ExtendedPoint {
    pub(crate) X: FieldElement,
    pub(crate) Y: FieldElement,
    pub(crate) Z: FieldElement,
    pub(crate) T: FieldElement,
}

impl ConstantTimeEq for ExtendedPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let XZ = self.X * other.Z;
        let ZX = self.Z * other.X;

        let YZ = self.Y * other.Z;
        let ZY = self.Z * other.Y;

        (XZ.ct_eq(&ZX)) & (YZ.ct_eq(&ZY))
    }
}

impl ConditionallySelectable for ExtendedPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ExtendedPoint {
            X: FieldElement::conditional_select(&a.X, &b.X, choice),
            Y: FieldElement::conditional_select(&a.Y, &b.Y, choice),
            Z: FieldElement::conditional_select(&a.Z, &b.Z, choice),
            T: FieldElement::conditional_select(&a.T, &b.T, choice),
        }
    }
}

impl PartialEq for ExtendedPoint {
    fn eq(&self, other: &ExtendedPoint) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for ExtendedPoint {}

impl Default for ExtendedPoint {
    fn default() -> ExtendedPoint {
        ExtendedPoint::IDENTITY
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for ExtendedPoint {}

impl ExtendedPoint {
    /// Generator for the prime subgroup
    pub const GENERATOR: ExtendedPoint = ExtendedPoint {
        X: crate::TWISTED_EDWARDS_BASE_POINT.X,
        Y: crate::TWISTED_EDWARDS_BASE_POINT.Y,
        Z: crate::TWISTED_EDWARDS_BASE_POINT.Z,
        T: crate::TWISTED_EDWARDS_BASE_POINT.T,
    };
    /// Identity point
    pub const IDENTITY: ExtendedPoint = ExtendedPoint {
        X: FieldElement::ZERO,
        Y: FieldElement::ONE,
        Z: FieldElement::ONE,
        T: FieldElement::ZERO,
    };

    /// Doubles an extended point
    pub(crate) fn double(&self) -> ExtendedPoint {
        self.to_extensible().double().to_extended()
    }

    /// Adds an extended point to itself
    pub(crate) fn add(&self, other: &ExtendedPoint) -> ExtendedPoint {
        self.to_extensible().add_extended(other).to_extended()
    }

    /// Converts an ExtendedPoint to an ExtensiblePoint
    pub fn to_extensible(self) -> ExtensiblePoint {
        ExtensiblePoint {
            X: self.X,
            Y: self.Y,
            Z: self.Z,
            T1: self.T,
            T2: FieldElement::ONE,
        }
    }

    /// Converts an extended point to Affine co-ordinates
    pub(crate) fn to_affine(self) -> AffinePoint {
        // Points to consider:
        // - All points where Z=0, translate to (0,0)
        // - The identity point has z=1, so it is not a problem

        let INV_Z = self.Z.invert();

        let x = self.X * INV_Z;
        let y = self.Y * INV_Z;

        AffinePoint { x, y }
    }

    /// Edwards_Isogeny is derived from the doubling formula
    /// XXX: There is a duplicate method in the twisted edwards module to compute the dual isogeny
    /// XXX: Not much point trying to make it generic I think. So what we can do is optimise each respective isogeny method for a=1 or a = -1 (currently, I just made it really slow and simple)
    fn edwards_isogeny(&self, a: FieldElement) -> EdwardsExtendedPoint {
        // Convert to affine now, then derive extended version later
        let affine = self.to_affine();
        let x = affine.x;
        let y = affine.y;

        // Compute x
        let xy = x * y;
        let x_numerator = xy + xy;
        let x_denom = y.square() - (a * x.square());
        let new_x = x_numerator * x_denom.invert();

        // Compute y
        let y_numerator = y.square() + (a * x.square());
        let y_denom = (FieldElement::ONE + FieldElement::ONE) - y.square() - (a * x.square());
        let new_y = y_numerator * y_denom.invert();

        EdwardsExtendedPoint {
            X: new_x,
            Y: new_y,
            Z: FieldElement::ONE,
            T: new_x * new_y,
        }
    }

    /// Uses a 2-isogeny to map the point to the Ed448-Goldilocks
    pub fn to_untwisted(self) -> EdwardsExtendedPoint {
        self.edwards_isogeny(FieldElement::MINUS_ONE)
    }

    /// Checks if the point is on the curve
    pub(crate) fn is_on_curve(&self) -> Choice {
        let XY = self.X * self.Y;
        let ZT = self.Z * self.T;

        // Y^2 - X^2 == Z^2 + T^2 * (TWISTED_D)

        let YY = self.Y.square();
        let XX = self.X.square();
        let ZZ = self.Z.square();
        let TT = self.T.square();
        let lhs = YY - XX;
        let rhs = ZZ + TT * FieldElement::TWISTED_D;

        XY.ct_eq(&ZT) & lhs.ct_eq(&rhs)
    }

    /// Negates a point
    pub fn negate(&self) -> ExtendedPoint {
        ExtendedPoint {
            X: -self.X,
            Y: self.Y,
            Z: self.Z,
            T: -self.T,
        }
    }

    /// Torques a point
    pub fn torque(&self) -> ExtendedPoint {
        ExtendedPoint {
            X: -self.X,
            Y: -self.Y,
            Z: self.Z,
            T: self.T,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GOLDILOCKS_BASE_POINT, TWISTED_EDWARDS_BASE_POINT};

    fn hex_to_field(hex: &'static str) -> FieldElement {
        assert_eq!(hex.len(), 56 * 2);
        let mut bytes = hex_literal::decode(&[hex.as_bytes()]);
        bytes.reverse();
        FieldElement::from_bytes(&bytes)
    }

    #[test]
    fn test_isogeny() {
        let x = hex_to_field("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555");
        let y = hex_to_field("ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed");
        let a = AffinePoint { x, y }.to_extended();
        let twist_a = a.to_untwisted().to_twisted();
        assert_eq!(twist_a, a.double().double())
    }

    #[test]
    fn test_is_on_curve() {
        // The twisted edwards basepoint should be on the curve
        // twisted edwards curve
        assert_eq!(TWISTED_EDWARDS_BASE_POINT.is_on_curve().unwrap_u8(), 1u8);

        // The goldilocks basepoint should not be
        let invalid_point = ExtendedPoint {
            X: GOLDILOCKS_BASE_POINT.X,
            Y: GOLDILOCKS_BASE_POINT.Y,
            Z: GOLDILOCKS_BASE_POINT.Z,
            T: GOLDILOCKS_BASE_POINT.T,
        };
        assert_eq!(invalid_point.is_on_curve().unwrap_u8(), 0u8);
    }

    #[test]
    fn test_point_add() {
        let a = TWISTED_EDWARDS_BASE_POINT;
        let b = a.double();

        // A + B = B + A = C
        let c_1 = a.to_extensible().add_extended(&b).to_extended();
        let c_2 = b.to_extensible().add_extended(&a).to_extended();
        assert!(c_1 == c_2);

        // Adding identity point should not change result
        let c = c_1.to_extensible().add_extended(&ExtendedPoint::IDENTITY);
        assert!(c.to_extended() == c_1);
    }

    #[test]
    fn test_point_sub() {
        let a = TWISTED_EDWARDS_BASE_POINT;
        let b = a.double();

        // A - B = C
        let c_1 = a.to_extensible().sub_extended(&b).to_extended();

        // -B + A = C
        let c_2 = b.negate().to_extensible().add_extended(&a).to_extended();
        assert!(c_1 == c_2);
    }

    #[test]
    fn test_negate() {
        let a = TWISTED_EDWARDS_BASE_POINT;
        let neg_a = a.negate();

        assert!(a.to_extensible().add_extended(&neg_a) == ExtensiblePoint::IDENTITY);
    }
}
