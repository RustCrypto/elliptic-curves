#![allow(non_snake_case)]

use crate::curve::twedwards::{extended::ExtendedPoint, extensible::ExtensiblePoint};
use crate::field::FieldElement;
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable};

impl Default for ProjectiveNielsPoint {
    fn default() -> ProjectiveNielsPoint {
        ProjectiveNielsPoint::identity()
    }
}

// Its a variant of Niels, where a Z coordinate is added for unmixed readdition
// ((y+x)/2, (y-x)/2, dxy, Z)
#[derive(Copy, Clone)]
pub struct ProjectiveNielsPoint {
    pub(crate) Y_plus_X: FieldElement,
    pub(crate) Y_minus_X: FieldElement,
    pub(crate) Td: FieldElement,
    pub(crate) Z: FieldElement,
}

impl PartialEq for ProjectiveNielsPoint {
    fn eq(&self, other: &ProjectiveNielsPoint) -> bool {
        self.to_extended().eq(&other.to_extended())
    }
}
impl Eq for ProjectiveNielsPoint {}

impl ConditionallySelectable for ProjectiveNielsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ProjectiveNielsPoint {
            Y_plus_X: FieldElement::conditional_select(&a.Y_plus_X, &b.Y_plus_X, choice),
            Y_minus_X: FieldElement::conditional_select(&a.Y_minus_X, &b.Y_minus_X, choice),
            Td: FieldElement::conditional_select(&a.Td, &b.Td, choice),
            Z: FieldElement::conditional_select(&a.Z, &b.Z, choice),
        }
    }
}
impl ConditionallyNegatable for ProjectiveNielsPoint {
    fn conditional_negate(&mut self, choice: Choice) {
        FieldElement::conditional_swap(&mut self.Y_minus_X, &mut self.Y_plus_X, choice);
        self.Td.conditional_negate(choice);
    }
}

impl ProjectiveNielsPoint {
    pub fn identity() -> ProjectiveNielsPoint {
        ExtensiblePoint::IDENTITY.to_projective_niels()
    }

    pub fn to_extended(self) -> ExtendedPoint {
        let A = self.Y_plus_X - self.Y_minus_X;
        let B = self.Y_plus_X + self.Y_minus_X;
        ExtendedPoint {
            X: self.Z * A,
            Y: self.Z * B,
            Z: self.Z.square(),
            T: B * A,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conditional_negate() {
        let bp = ExtendedPoint::GENERATOR;

        let mut bp_neg = bp.to_extensible().to_projective_niels();
        bp_neg.conditional_negate(1.into());

        let expect_identity = bp_neg.to_extended().add(&bp);
        assert_eq!(ExtendedPoint::IDENTITY, expect_identity);
    }
}
