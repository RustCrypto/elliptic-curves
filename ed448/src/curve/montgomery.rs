// The original file was a part of curve25519-dalek.
// Copyright (c) 2016-2019 Isis Lovecruft, Henry de Valence
// Copyright (c) 2020 Kevaundray Wedderburn
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>
// - Kevaundray Wedderburn <kevtheappdev@gmail.com>

#![allow(non_snake_case)]

// use crate::constants::A_PLUS_TWO_OVER_FOUR;
use crate::curve::edwards::extended::EdwardsPoint;
use crate::field::{FieldElement, Scalar};
use core::fmt;
use core::ops::Mul;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

// Low order points on Curve448 and it's twist
const LOW_A: MontgomeryPoint = MontgomeryPoint([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
const LOW_B: MontgomeryPoint = MontgomeryPoint([
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
const LOW_C: MontgomeryPoint = MontgomeryPoint([
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
]);

/// A point in Montgomery form
#[derive(Copy, Clone)]
pub struct MontgomeryPoint(pub [u8; 56]);

impl Default for MontgomeryPoint {
    fn default() -> MontgomeryPoint {
        Self([0u8; 56])
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for MontgomeryPoint {}

impl fmt::Debug for MontgomeryPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.0[..].fmt(formatter)
    }
}

impl ConstantTimeEq for MontgomeryPoint {
    fn ct_eq(&self, other: &MontgomeryPoint) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for MontgomeryPoint {
    fn eq(&self, other: &MontgomeryPoint) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for MontgomeryPoint {}

/// A Projective point in Montgomery form
#[derive(Copy, Clone, Debug)]
pub struct ProjectiveMontgomeryPoint {
    U: FieldElement,
    W: FieldElement,
}

impl Mul<&Scalar> for &MontgomeryPoint {
    type Output = MontgomeryPoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, scalar: &Scalar) -> MontgomeryPoint {
        // Algorithm 8 of Costello-Smith 2017
        let affine_u = FieldElement::from_bytes(&self.0);
        let mut x0 = ProjectiveMontgomeryPoint::identity();
        let mut x1 = ProjectiveMontgomeryPoint {
            U: affine_u,
            W: FieldElement::ONE,
        };

        let bits = scalar.bits();
        let mut swap = 0;
        for s in (0..448).rev() {
            let bit = bits[s] as u8;
            let choice: u8 = swap ^ bit;

            ProjectiveMontgomeryPoint::conditional_swap(&mut x0, &mut x1, Choice::from(choice));
            differential_add_and_double(&mut x0, &mut x1, &affine_u);

            swap = bit;
        }

        x0.to_affine()
    }
}

impl Mul<&MontgomeryPoint> for &Scalar {
    type Output = MontgomeryPoint;

    fn mul(self, point: &MontgomeryPoint) -> MontgomeryPoint {
        point * self
    }
}

impl MontgomeryPoint {
    /// Returns the generator specified in RFC7748
    pub const GENERATOR: Self = Self([
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    /// Convert this point to an [`EdwardsPoint`]
    pub fn to_edwards(&self, _sign: u8) -> Option<EdwardsPoint> {
        // We use the 4-isogeny to map to the Ed448.
        // This is different to Curve25519, where we use a birational map.
        todo!()
    }

    /// Returns true if the point is one of the low order points
    pub fn is_low_order(&self) -> bool {
        (*self == LOW_A) || (*self == LOW_B) || (*self == LOW_C)
    }

    /// View the point as a byte slice
    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.0
    }

    /// Convert the point to a ProjectiveMontgomeryPoint
    pub fn to_projective(&self) -> ProjectiveMontgomeryPoint {
        ProjectiveMontgomeryPoint {
            U: FieldElement::from_bytes(&self.0),
            W: FieldElement::ONE,
        }
    }
}

impl ConditionallySelectable for ProjectiveMontgomeryPoint {
    fn conditional_select(
        a: &ProjectiveMontgomeryPoint,
        b: &ProjectiveMontgomeryPoint,
        choice: Choice,
    ) -> ProjectiveMontgomeryPoint {
        ProjectiveMontgomeryPoint {
            U: FieldElement::conditional_select(&a.U, &b.U, choice),
            W: FieldElement::conditional_select(&a.W, &b.W, choice),
        }
    }
}

fn differential_add_and_double(
    P: &mut ProjectiveMontgomeryPoint,
    Q: &mut ProjectiveMontgomeryPoint,
    affine_PmQ: &FieldElement,
) {
    let t0 = P.U + P.W;
    let t1 = P.U - P.W;
    let t2 = Q.U + Q.W;
    let t3 = Q.U - Q.W;

    let t4 = t0.square(); // (U_P + W_P)^2 = U_P^2 + 2 U_P W_P + W_P^2
    let t5 = t1.square(); // (U_P - W_P)^2 = U_P^2 - 2 U_P W_P + W_P^2

    let t6 = t4 - t5; // 4 U_P W_P

    let t7 = t0 * t3; // (U_P + W_P) (U_Q - W_Q) = U_P U_Q + W_P U_Q - U_P W_Q - W_P W_Q
    let t8 = t1 * t2; // (U_P - W_P) (U_Q + W_Q) = U_P U_Q - W_P U_Q + U_P W_Q - W_P W_Q

    let t9 = t7 + t8; // 2 (U_P U_Q - W_P W_Q)
    let t10 = t7 - t8; // 2 (W_P U_Q - U_P W_Q)

    let t11 = t9.square(); // 4 (U_P U_Q - W_P W_Q)^2
    let t12 = t10.square(); // 4 (W_P U_Q - U_P W_Q)^2
    let t13 = FieldElement::A_PLUS_TWO_OVER_FOUR * t6; // (A + 2) U_P U_Q

    let t14 = t4 * t5; // ((U_P + W_P)(U_P - W_P))^2 = (U_P^2 - W_P^2)^2
    let t15 = t13 + t5; // (U_P - W_P)^2 + (A + 2) U_P W_P

    let t16 = t6 * t15; // 4 (U_P W_P) ((U_P - W_P)^2 + (A + 2) U_P W_P)
    let t17 = *affine_PmQ * t12; // U_D * 4 (W_P U_Q - U_P W_Q)^2
    let t18 = t11; // W_D * 4 (U_P U_Q - W_P W_Q)^2

    P.U = t14; // U_{P'} = (U_P + W_P)^2 (U_P - W_P)^2
    P.W = t16; // W_{P'} = (4 U_P W_P) ((U_P - W_P)^2 + ((A + 2)/4) 4 U_P W_P)
    Q.U = t18; // U_{Q'} = W_D * 4 (U_P U_Q - W_P W_Q)^2
    Q.W = t17; // W_{Q'} = U_D * 4 (W_P U_Q - U_P W_Q)^2
}

impl ProjectiveMontgomeryPoint {
    /// The identity element of the group: the point at infinity.
    pub fn identity() -> ProjectiveMontgomeryPoint {
        ProjectiveMontgomeryPoint {
            U: FieldElement::ONE,
            W: FieldElement::ZERO,
        }
    }

    /// Convert the point to affine form
    pub fn to_affine(&self) -> MontgomeryPoint {
        let x = self.U * self.W.invert();
        MontgomeryPoint(x.to_bytes())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_montgomery_edwards() {
        let scalar = Scalar::from(200u32);
        use crate::GOLDILOCKS_BASE_POINT as bp;

        // Montgomery scalar mul
        let montgomery_bp = bp.to_montgomery();
        let montgomery_res = &montgomery_bp * &scalar;

        // Goldilocks scalar mul
        let goldilocks_point = bp.scalar_mul(&scalar);
        assert_eq!(goldilocks_point.to_montgomery(), montgomery_res);
    }
}
