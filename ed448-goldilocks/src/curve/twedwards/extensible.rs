#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::curve::twedwards::{
    affine::AffineNielsPoint, extended::ExtendedPoint, projective::ProjectiveNielsPoint,
};
use crate::field::FieldElement;
use subtle::{Choice, ConstantTimeEq};

/// This is the representation that we will do most of the group operations on.
// In affine (x,y) is the extensible point (X, Y, Z, T1, T2)
// Where x = X/Z , y = Y/Z , T1 * T2 = T
// XXX: I think we have too many point representations,
// But let's not remove any yet
pub struct ExtensiblePoint {
    pub(crate) X: FieldElement,
    pub(crate) Y: FieldElement,
    pub(crate) Z: FieldElement,
    pub(crate) T1: FieldElement,
    pub(crate) T2: FieldElement,
}

impl ConstantTimeEq for ExtensiblePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let XZ = self.X * other.Z;
        let ZX = self.Z * other.X;

        let YZ = self.Y * other.Z;
        let ZY = self.Z * other.Y;

        XZ.ct_eq(&ZX) & YZ.ct_eq(&ZY)
    }
}
impl PartialEq for ExtensiblePoint {
    fn eq(&self, other: &ExtensiblePoint) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for ExtensiblePoint {}

impl ExtensiblePoint {
    pub const IDENTITY: ExtensiblePoint = ExtensiblePoint {
        X: FieldElement::ZERO,
        Y: FieldElement::ONE,
        Z: FieldElement::ONE,
        T1: FieldElement::ZERO,
        T2: FieldElement::ONE,
    };

    /// Doubles a point
    /// (3.3) https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
    pub fn double(&self) -> ExtensiblePoint {
        let A = self.X.square();
        let B = self.Y.square();
        let C = self.Z.square() + self.Z.square();
        let D = -A;
        let E = (self.X + self.Y).square() - A - B;
        let G = D + B;
        let F = G - C;
        let H = D - B;
        ExtensiblePoint {
            X: E * F,
            Y: G * H,
            Z: F * G,
            T1: E,
            T2: H,
        }
    }

    /// Adds two extensible points together by converting the other point to a ExtendedPoint
    pub fn add_extensible(&self, other: &ExtensiblePoint) -> ExtensiblePoint {
        self.add_extended(&other.to_extended())
    }

    /// Adds an extensible point to an extended point
    /// Returns an extensible point
    /// (3.1) https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf
    pub fn add_extended(&self, other: &ExtendedPoint) -> ExtensiblePoint {
        let A = self.X * other.X;
        let B = self.Y * other.Y;
        let C = self.T1 * self.T2 * other.T * FieldElement::TWISTED_D;
        let D = self.Z * other.Z;
        let E = (self.X + self.Y) * (other.X + other.Y) - A - B;
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

    /// Subtracts an extensible point from an extended point
    /// Returns an extensible point
    /// This is a direct modification of the addition formula to the negation of `other`
    pub fn sub_extended(&self, other: &ExtendedPoint) -> ExtensiblePoint {
        let A = self.X * other.X;
        let B = self.Y * other.Y;
        let C = self.T1 * self.T2 * other.T * FieldElement::TWISTED_D;
        let D = self.Z * other.Z;
        let E = (self.X + self.Y) * (other.Y - other.X) + A - B;
        let F = D + C;
        let G = D - C;
        let H = B - A;
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
        let C = other.td * self.T1 * self.T2;
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
        let C = other.Td * self.T1 * self.T2;
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

    /// Converts an extensible point to an extended point
    pub fn to_extended(&self) -> ExtendedPoint {
        ExtendedPoint {
            X: self.X,
            Y: self.Y,
            Z: self.Z,
            T: self.T1 * self.T2,
        }
    }

    /// Converts an Extensible point to a ProjectiveNiels Point
    pub fn to_projective_niels(&self) -> ProjectiveNielsPoint {
        ProjectiveNielsPoint {
            Y_plus_X: self.X + self.Y,
            Y_minus_X: self.Y - self.X,
            Z: self.Z + self.Z,
            Td: self.T1 * self.T2 * FieldElement::TWO_TIMES_TWISTED_D,
        }
    }
}
