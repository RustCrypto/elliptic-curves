#![allow(non_snake_case)]
#![allow(dead_code)]

use super::IsogenyMap;
use super::extensible::ExtensiblePoint;
use super::projective::ProjectiveNielsPoint;
use super::{IsogenyMapResult, affine::AffineNielsPoint};
use crate::edwards::EdwardsPoint as EdwardsExtendedPoint;
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
impl PartialEq<ExtensiblePoint> for ExtendedPoint {
    fn eq(&self, other: &ExtensiblePoint) -> bool {
        self.to_extensible().ct_eq(other).into()
    }
}
impl Eq for ExtendedPoint {}

impl Default for ExtendedPoint {
    fn default() -> ExtendedPoint {
        ExtendedPoint::IDENTITY
    }
}

impl elliptic_curve::zeroize::DefaultIsZeroes for ExtendedPoint {}

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

    /// Adds an extensible point to an extended point
    /// Returns an extensible point
    /// (3.1) https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
    pub fn add_extended(&self, other: &ExtendedPoint) -> ExtensiblePoint {
        let A = (self.Y - self.X) * (other.Y - other.X);
        let B = (self.Y + self.X) * (other.Y + other.X);
        let C = FieldElement::TWO_TIMES_TWISTED_D * self.T * other.T;
        let D = (self.Z * other.Z).double();
        let E = B - A;
        let F = D - C;
        let G = D + C;
        let H = B + A;
        ExtensiblePoint {
            X: E * F,
            Y: G * H,
            T1: E,
            T2: H,
            Z: F * G,
        }
    }

    /// Adds an extensible point to an AffineNiels point
    /// Returns an Extensible point
    pub fn add_affine_niels(&self, other: AffineNielsPoint) -> ExtensiblePoint {
        let A = other.y_minus_x * (self.Y - self.X);
        let B = other.y_plus_x * (self.X + self.Y);
        let C = other.td * self.T;
        let D = B + A;
        let E = B - A;
        let F = self.Z - C;
        let G = self.Z + C;
        ExtensiblePoint {
            X: E * F,
            Y: G * D,
            Z: F * G,
            T1: E,
            T2: D,
        }
    }

    /// Adds an extensible point to a ProjectiveNiels point
    /// Returns an extensible point
    /// (3.1)[Last set of formulas] https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
    /// This differs from the formula above by a factor of 2. Saving 1 Double
    /// Cost 8M
    pub fn add_projective_niels(&self, other: &ProjectiveNielsPoint) -> ExtensiblePoint {
        // This is the only step which makes it different than adding an AffineNielsPoint
        let Z = self.Z * other.Z;

        let A = (self.Y - self.X) * other.Y_minus_X;
        let B = (self.Y + self.X) * other.Y_plus_X;
        let C = other.Td * self.T;
        let D = B + A;
        let E = B - A;
        let F = Z - C;
        let G = Z + C;
        ExtensiblePoint {
            X: E * F,
            Y: G * D,
            Z: F * G,
            T1: E,
            T2: D,
        }
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

    /// Uses a 2-isogeny to map the point to the Ed448-Goldilocks
    pub fn to_untwisted(self) -> EdwardsExtendedPoint {
        let IsogenyMapResult { X, Y, Z, T1, T2 } = IsogenyMap {
            X: self.X,
            Y: self.Y,
            Z: self.Z,
            T: self.T,
        }
        .map(|f| -f);

        EdwardsExtendedPoint {
            X,
            Y,
            Z,
            T: T1 * T2,
        }
    }

    /// Converts an Extensible point to a ProjectiveNiels Point
    pub fn to_projective_niels(self) -> ProjectiveNielsPoint {
        ProjectiveNielsPoint {
            Y_plus_X: self.X + self.Y,
            Y_minus_X: self.Y - self.X,
            Z: self.Z.double(),
            Td: self.T * FieldElement::TWO_TIMES_TWISTED_D,
        }
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
    use crate::curve::twedwards::affine::AffinePoint;
    use crate::{GOLDILOCKS_BASE_POINT, TWISTED_EDWARDS_BASE_POINT};

    fn hex_to_field(hex: &'static str) -> FieldElement {
        assert_eq!(hex.len(), 56 * 2);
        let mut bytes =
            hex_literal::decode(&[hex.as_bytes()]).expect("Output array length should be correct");
        bytes.reverse();
        FieldElement::from_bytes(&bytes)
    }

    #[test]
    fn test_isogeny() {
        let x = hex_to_field(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555",
        );
        let y = hex_to_field(
            "ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed",
        );
        let a = AffinePoint { x, y }.to_extensible();
        let twist_a = a.to_extended().to_untwisted().to_twisted();
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
        let b = a.to_extensible().double().to_extended();

        // A + B = B + A = C
        let c_1 = a.add_extended(&b).to_extended();
        let c_2 = b.add_extended(&a).to_extended();
        assert!(c_1 == c_2);

        // Adding identity point should not change result
        let c = c_1.add_extended(&ExtendedPoint::IDENTITY);
        assert!(c == c_1);
    }

    #[test]
    fn test_negate() {
        let a = TWISTED_EDWARDS_BASE_POINT;
        let neg_a = a.negate();

        assert!(a.add_extended(&neg_a) == ExtensiblePoint::IDENTITY);
    }
}
