use elliptic_curve::bigint::U448;
use subtle::Choice;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

use super::{MontgomeryXpoint, ProjectiveMontgomeryXpoint};
use crate::AffinePoint;
use crate::field::ConstMontyType;
use crate::field::FieldElement;

/// A point in Montgomery form including the y-coordinate.
#[derive(Copy, Clone, Debug, Default)]
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

    /// Convert this point to an [`AffinePoint`]
    // https://www.rfc-editor.org/rfc/rfc7748#section-4.2
    pub fn to_edwards(&self) -> AffinePoint {
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

        let x = xNum * xDen.invert();
        let y = yNum * yDen.invert();

        AffinePoint::conditional_select(
            &AffinePoint { x, y },
            &AffinePoint::IDENTITY,
            self.ct_eq(&Self::IDENTITY),
        )
    }

    /// Convert the point to its form without the y-coordinate
    pub fn to_affine_x(&self) -> MontgomeryXpoint {
        MontgomeryXpoint(self.x.to_bytes())
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
impl Eq for MontgomeryPoint {}

impl From<ProjectiveMontgomeryPoint> for MontgomeryPoint {
    fn from(value: ProjectiveMontgomeryPoint) -> Self {
        value.to_affine()
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

    /// Convert the point to its form without the y-coordinate
    pub fn to_projective_x(&self) -> ProjectiveMontgomeryXpoint {
        ProjectiveMontgomeryXpoint::conditional_select(
            &ProjectiveMontgomeryXpoint {
                U: self.U,
                W: self.W,
            },
            &ProjectiveMontgomeryXpoint::IDENTITY,
            self.ct_eq(&Self::IDENTITY),
        )
    }

    /// Convert the point to affine form without the y-coordinate
    pub fn to_affine_x(&self) -> MontgomeryXpoint {
        self.to_projective_x().to_affine()
    }

    /// Convert the point to affine form
    pub fn to_affine(&self) -> MontgomeryPoint {
        let W_inv = self.W.invert();
        let x = self.U * W_inv;
        let y = self.V * W_inv;

        MontgomeryPoint { x, y }
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
        self.U.ct_eq(&other.U) & self.V.ct_eq(&other.V) & self.W.ct_eq(&other.W)
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

impl From<MontgomeryPoint> for ProjectiveMontgomeryPoint {
    fn from(value: MontgomeryPoint) -> Self {
        ProjectiveMontgomeryPoint {
            U: value.x,
            V: value.y,
            W: FieldElement::ONE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EdwardsPoint, MontgomeryScalar};

    #[test]
    fn to_edwards() {
        let scalar = MontgomeryScalar::from(200u32);

        // Montgomery scalar mul
        let montgomery_res = ProjectiveMontgomeryPoint::GENERATOR * scalar * scalar;
        // Goldilocks scalar mul
        let goldilocks_point = EdwardsPoint::GENERATOR * scalar.to_scalar() * scalar.to_scalar();

        assert_eq!(goldilocks_point.to_montgomery(), montgomery_res.to_affine());
    }

    #[test]
    fn identity_to_edwards() {
        let edwards = AffinePoint::IDENTITY;
        let montgomery = MontgomeryPoint::IDENTITY;

        assert_eq!(montgomery.to_edwards(), edwards);
    }

    #[test]
    fn identity_from_montgomery() {
        let edwards = EdwardsPoint::IDENTITY;
        let montgomery = MontgomeryPoint::IDENTITY;

        assert_eq!(edwards.to_montgomery(), montgomery);
    }

    #[test]
    fn to_projective_x() {
        let x_identity = ProjectiveMontgomeryXpoint::IDENTITY;
        let identity = ProjectiveMontgomeryPoint::IDENTITY;

        assert_eq!(identity.to_projective_x(), x_identity);
    }

    #[test]
    fn to_affine_x() {
        let x_identity = ProjectiveMontgomeryXpoint::IDENTITY.to_affine();
        let identity = ProjectiveMontgomeryPoint::IDENTITY.to_affine_x();

        assert_eq!(identity, x_identity);
    }
}
