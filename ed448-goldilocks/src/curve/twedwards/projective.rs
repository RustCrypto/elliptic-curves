#![allow(non_snake_case)]

use super::extensible::ExtensiblePoint;
use crate::field::FieldElement;
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable};

impl Default for ProjectiveNielsPoint {
    fn default() -> ProjectiveNielsPoint {
        ProjectiveNielsPoint::IDENTITY
    }
}

// Its a variant of Niels, where a Z coordinate is added for unmixed readdition
// ((y+x)/2, (y-x)/2, dxy, Z)
#[derive(Copy, Clone, Debug)]
pub struct ProjectiveNielsPoint {
    pub(crate) Y_plus_X: FieldElement,
    pub(crate) Y_minus_X: FieldElement,
    pub(crate) Td: FieldElement,
    pub(crate) Z: FieldElement,
}

impl PartialEq for ProjectiveNielsPoint {
    fn eq(&self, other: &ProjectiveNielsPoint) -> bool {
        self.to_extensible().eq(&other.to_extensible())
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
    pub const IDENTITY: ProjectiveNielsPoint = ProjectiveNielsPoint {
        Y_plus_X: FieldElement::ONE,
        Y_minus_X: FieldElement::ONE,
        Td: FieldElement::ZERO,
        Z: FieldElement::TWO,
    };

    pub fn to_extensible(self) -> ExtensiblePoint {
        let A = self.Y_plus_X - self.Y_minus_X;
        let B = self.Y_plus_X + self.Y_minus_X;
        ExtensiblePoint {
            X: self.Z * A,
            Y: self.Z * B,
            Z: self.Z.square(),
            T1: B,
            T2: A,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::twedwards::extended::ExtendedPoint;

    #[test]
    fn identity() {
        // Internally are compared by converting to `ExtendedPoint`.
        // Here the right-side identity point is converted to Niel's
        // and then both sides are converted to twisted-curve form.
        assert_eq!(
            ProjectiveNielsPoint::IDENTITY,
            ExtendedPoint::IDENTITY.to_projective_niels(),
        );
        // Here only the left-side identity point is converted.
        assert_eq!(
            ProjectiveNielsPoint::IDENTITY.to_extensible(),
            ExtendedPoint::IDENTITY,
        );
    }

    #[test]
    fn test_conditional_negate() {
        let bp = ExtendedPoint::GENERATOR;

        let mut bp_neg = bp.to_projective_niels();
        bp_neg.conditional_negate(1.into());

        let expect_identity = bp_neg.to_extensible().to_extended().add_extended(&bp);
        assert_eq!(ExtendedPoint::IDENTITY, expect_identity);
    }
}
