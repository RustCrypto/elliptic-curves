use elliptic_curve::bigint::U448;
use subtle::Choice;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

use super::{MontgomeryXpoint, ProjectiveMontgomeryXpoint};
use crate::field::{ConstMontyType, FieldElement};

/// A point in Montgomery form including the y-coordinate.
#[derive(Copy, Clone, Debug, Default, Eq)]
pub struct MontgomeryPoint {
    pub(super) x: FieldElement,
    pub(super) y: FieldElement,
}

impl MontgomeryPoint {
    /// The identity element of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
    };

    pub(crate) fn new(x: FieldElement, y: FieldElement) -> Self {
        Self { x, y }
    }
}

impl ConditionallySelectable for MontgomeryPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
        }
    }
}

impl ConstantTimeEq for MontgomeryPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
    }
}

impl PartialEq for MontgomeryPoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl From<&MontgomeryPoint> for ProjectiveMontgomeryPoint {
    fn from(value: &MontgomeryPoint) -> Self {
        ProjectiveMontgomeryPoint {
            U: value.x,
            V: value.y,
            W: FieldElement::ONE,
        }
    }
}

impl From<MontgomeryPoint> for ProjectiveMontgomeryPoint {
    fn from(value: MontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl From<&MontgomeryPoint> for MontgomeryXpoint {
    fn from(value: &MontgomeryPoint) -> Self {
        MontgomeryXpoint(value.x.to_bytes())
    }
}

impl From<MontgomeryPoint> for MontgomeryXpoint {
    fn from(value: MontgomeryPoint) -> Self {
        (&value).into()
    }
}

/// A Projective point in Montgomery form including the y-coordinate.
#[derive(Copy, Clone, Debug, Eq)]
pub struct ProjectiveMontgomeryPoint {
    pub(super) U: FieldElement,
    pub(super) V: FieldElement,
    pub(super) W: FieldElement,
}

impl ProjectiveMontgomeryPoint {
    /// The identity element of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        U: FieldElement::ZERO,
        V: FieldElement::ONE,
        W: FieldElement::ZERO,
    };

    /// The generator point
    pub const GENERATOR: Self = Self {
        U: FieldElement(ConstMontyType::new(&U448::from_u64(5))),
        V: FieldElement(ConstMontyType::new(&U448::from_be_hex(
            "7d235d1295f5b1f66c98ab6e58326fcecbae5d34f55545d060f75dc28df3f6edb8027e2346430d211312c4b150677af76fd7223d457b5b1a",
        ))),
        W: FieldElement::ONE,
    };

    pub(crate) fn new(U: FieldElement, V: FieldElement, W: FieldElement) -> Self {
        Self { U, V, W }
    }
}

impl ConditionallySelectable for ProjectiveMontgomeryPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            U: FieldElement::conditional_select(&a.U, &b.U, choice),
            V: FieldElement::conditional_select(&a.V, &b.V, choice),
            W: FieldElement::conditional_select(&a.W, &b.W, choice),
        }
    }
}

impl ConstantTimeEq for ProjectiveMontgomeryPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let UW = self.U * other.W;
        let WU = self.W * other.U;

        let VW = self.V * other.W;
        let WV = self.W * other.V;

        (UW.ct_eq(&WU)) & (VW.ct_eq(&WV))
    }
}

impl Default for ProjectiveMontgomeryPoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl PartialEq for ProjectiveMontgomeryPoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl From<&ProjectiveMontgomeryPoint> for MontgomeryPoint {
    fn from(value: &ProjectiveMontgomeryPoint) -> Self {
        let W_inv = value.W.invert();
        let x = value.U * W_inv;
        let y = value.V * W_inv;

        MontgomeryPoint { x, y }
    }
}

impl From<ProjectiveMontgomeryPoint> for MontgomeryPoint {
    fn from(value: ProjectiveMontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl From<&ProjectiveMontgomeryPoint> for ProjectiveMontgomeryXpoint {
    fn from(value: &ProjectiveMontgomeryPoint) -> Self {
        ProjectiveMontgomeryXpoint::conditional_select(
            &ProjectiveMontgomeryXpoint {
                U: value.U,
                W: value.W,
            },
            &ProjectiveMontgomeryXpoint::IDENTITY,
            value.ct_eq(&ProjectiveMontgomeryPoint::IDENTITY),
        )
    }
}

impl From<ProjectiveMontgomeryPoint> for ProjectiveMontgomeryXpoint {
    fn from(value: ProjectiveMontgomeryPoint) -> Self {
        (&value).into()
    }
}

impl From<&ProjectiveMontgomeryPoint> for MontgomeryXpoint {
    fn from(value: &ProjectiveMontgomeryPoint) -> Self {
        ProjectiveMontgomeryXpoint::from(value).to_affine()
    }
}

impl From<ProjectiveMontgomeryPoint> for MontgomeryXpoint {
    fn from(value: ProjectiveMontgomeryPoint) -> Self {
        (&value).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_projective_x() {
        let x_identity = ProjectiveMontgomeryXpoint::IDENTITY;
        let identity = ProjectiveMontgomeryPoint::IDENTITY;

        assert_eq!(ProjectiveMontgomeryXpoint::from(identity), x_identity);
    }

    #[test]
    fn to_affine_x() {
        let x_identity = ProjectiveMontgomeryXpoint::IDENTITY.to_affine();
        let identity = MontgomeryXpoint::from(ProjectiveMontgomeryPoint::IDENTITY);

        assert_eq!(identity, x_identity);
    }
}
