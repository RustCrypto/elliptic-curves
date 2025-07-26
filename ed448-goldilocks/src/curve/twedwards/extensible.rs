#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::curve::twedwards::{affine::AffinePoint, extended::ExtendedPoint};
use crate::edwards::EdwardsPoint as EdwardsExtendedPoint;
use crate::field::FieldElement;
use subtle::{Choice, ConstantTimeEq};

/// This is the representation that we will do most of the group operations on.
// In affine (x,y) is the extensible point (X, Y, Z, T1, T2)
// Where x = X/Z , y = Y/Z , T1 * T2 = T
// XXX: I think we have too many point representations,
// But let's not remove any yet
#[derive(Copy, Clone, Debug)]
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
impl PartialEq<ExtendedPoint> for ExtensiblePoint {
    fn eq(&self, other: &ExtendedPoint) -> bool {
        self.ct_eq(&other.to_extensible()).into()
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
        let C = self.Z.square().double();
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

    /// Converts an extensible point to an extended point
    pub fn to_extended(self) -> ExtendedPoint {
        ExtendedPoint {
            X: self.X,
            Y: self.Y,
            Z: self.Z,
            T: self.T1 * self.T2,
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
        let x_numerator = xy.double();
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
}
