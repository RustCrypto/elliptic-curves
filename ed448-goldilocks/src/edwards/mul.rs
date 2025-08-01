use super::{EdwardsPoint, EdwardsScalar};
use crate::field::FieldElement;
use core::ops::Add;
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

pub(super) fn scalar_mul(point: &EdwardsPoint, scalar: &EdwardsScalar) -> EdwardsPoint {
    let mut result = ExtensiblePoint::IDENTITY;

    // Recode Scalar
    let scalar = scalar.to_radix_16();

    let lookup = LookupTable::from(point);

    for i in (0..113).rev() {
        result = result.double();
        result = result.double();
        result = result.double();
        result = result.double();

        // The mask is the top bit, will be 1 for negative numbers, 0 for positive numbers
        let mask = scalar[i] >> 7;
        let sign = mask & 0x1;
        // Use the mask to get the absolute value of scalar
        let abs_value = ((scalar[i] + mask) ^ mask) as u32;

        let mut neg_P = lookup.select(abs_value);
        neg_P.conditional_negate(Choice::from((sign) as u8));

        result = &EdwardsPoint::from(result) + &neg_P;
    }

    result.into()
}

struct ExtensiblePoint {
    X: FieldElement,
    Y: FieldElement,
    Z: FieldElement,
    T1: FieldElement,
    T2: FieldElement,
}

impl ExtensiblePoint {
    const IDENTITY: ExtensiblePoint = ExtensiblePoint {
        X: FieldElement::ZERO,
        Y: FieldElement::ONE,
        Z: FieldElement::ONE,
        T1: FieldElement::ZERO,
        T2: FieldElement::ONE,
    };

    fn double(&self) -> Self {
        let A = self.X.square();
        let B = self.Y.square();
        let C = self.Z.square().double();
        let D = A;
        let E = (self.X + self.Y).square() - A - B;
        let G = D + B;
        let F = G - C;
        let H = D - B;
        Self {
            X: E * F,
            Y: G * H,
            Z: F * G,
            T1: E,
            T2: H,
        }
    }
}

impl From<ExtensiblePoint> for EdwardsPoint {
    fn from(value: ExtensiblePoint) -> Self {
        Self {
            X: value.X,
            Y: value.Y,
            Z: value.Z,
            T: value.T1 * value.T2,
        }
    }
}

impl From<EdwardsPoint> for ExtensiblePoint {
    fn from(value: EdwardsPoint) -> Self {
        Self {
            X: value.X,
            Y: value.Y,
            Z: value.Z,
            T1: value.T,
            T2: FieldElement::ONE,
        }
    }
}

#[derive(Clone, Copy)]
struct MixedAdditionPoint {
    X: FieldElement,
    Y: FieldElement,
    Z: FieldElement,
    Td: FieldElement,
}

impl MixedAdditionPoint {
    const IDENTITY: Self = Self {
        X: FieldElement::ZERO,
        Y: FieldElement::ONE,
        Z: FieldElement::ONE,
        Td: FieldElement::ZERO,
    };
}

impl From<&EdwardsPoint> for MixedAdditionPoint {
    fn from(value: &EdwardsPoint) -> Self {
        Self {
            X: value.X,
            Y: value.Y,
            Z: value.Z,
            Td: value.T * FieldElement::EDWARDS_D,
        }
    }
}

impl From<EdwardsPoint> for MixedAdditionPoint {
    fn from(value: EdwardsPoint) -> Self {
        (&value).into()
    }
}

impl Add<&MixedAdditionPoint> for &EdwardsPoint {
    type Output = ExtensiblePoint;

    fn add(self, rhs: &MixedAdditionPoint) -> Self::Output {
        let A = self.X * rhs.X;
        let B = self.Y * rhs.Y;
        let C = self.T * rhs.Td;
        let D = self.Z * rhs.Z;
        let E = (self.X + self.Y) * (rhs.X + rhs.Y) - A - B;
        let F = D - C;
        let G = D + C;
        let H = B - A;
        ExtensiblePoint {
            X: E * F,
            Y: G * H,
            Z: F * G,
            T1: E,
            T2: H,
        }
    }
}

impl ConditionallySelectable for MixedAdditionPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            X: FieldElement::conditional_select(&a.X, &b.X, choice),
            Y: FieldElement::conditional_select(&a.Y, &b.Y, choice),
            Z: FieldElement::conditional_select(&a.Z, &b.Z, choice),
            Td: FieldElement::conditional_select(&a.Td, &b.Td, choice),
        }
    }
}

impl ConditionallyNegatable for MixedAdditionPoint {
    fn conditional_negate(&mut self, choice: Choice) {
        self.X.conditional_negate(choice);
        self.Td.conditional_negate(choice);
    }
}

struct LookupTable([MixedAdditionPoint; 8]);

/// Precomputes odd multiples of the point passed in
impl From<&EdwardsPoint> for LookupTable {
    fn from(P: &EdwardsPoint) -> LookupTable {
        let mut table = [MixedAdditionPoint::from(P); 8];

        for i in 1..8 {
            table[i] = EdwardsPoint::from(P + &table[i - 1]).into();
        }

        LookupTable(table)
    }
}

impl LookupTable {
    /// Selects a projective niels point from a lookup table in constant time
    fn select(&self, index: u32) -> MixedAdditionPoint {
        let mut result = MixedAdditionPoint::IDENTITY;

        for i in 1..9 {
            let swap = index.ct_eq(&(i as u32));
            result.conditional_assign(&self.0[i - 1], swap);
        }
        result
    }
}
