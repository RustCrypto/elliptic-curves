#![allow(non_snake_case)]
#![allow(dead_code)]

use super::affine::AffinePoint;
use super::extended::ExtendedPoint;
use crate::field::FieldElement;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

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
impl ConditionallySelectable for ExtensiblePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            X: FieldElement::conditional_select(&a.X, &b.X, choice),
            Y: FieldElement::conditional_select(&a.Y, &b.Y, choice),
            Z: FieldElement::conditional_select(&a.Z, &b.Z, choice),
            T1: FieldElement::conditional_select(&a.T1, &b.T1, choice),
            T2: FieldElement::conditional_select(&a.T2, &b.T2, choice),
        }
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
}
