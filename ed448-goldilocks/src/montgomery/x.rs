// use crate::constants::A_PLUS_TWO_OVER_FOUR;
use super::{MontgomeryPoint, MontgomeryScalar, ProjectiveMontgomeryPoint};
use crate::edwards::extended::EdwardsPoint;
use crate::field::{ConstMontyType, FieldElement};
use core::fmt;
use core::ops::Mul;
use elliptic_curve::bigint::U448;
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

impl MontgomeryXpoint {
    /// First low order point on Curve448 and it's twist
    pub const LOW_A: MontgomeryXpoint = MontgomeryXpoint([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    /// Second low order point on Curve448 and it's twist
    pub const LOW_B: MontgomeryXpoint = MontgomeryXpoint([
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    /// Third low order point on Curve448 and it's twist
    pub const LOW_C: MontgomeryXpoint = MontgomeryXpoint([
        0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]);
}

/// A point in Montgomery form
#[derive(Copy, Clone)]
pub struct MontgomeryXpoint(pub [u8; 56]);

impl Default for MontgomeryXpoint {
    fn default() -> MontgomeryXpoint {
        Self([0u8; 56])
    }
}

impl elliptic_curve::zeroize::DefaultIsZeroes for MontgomeryXpoint {}

impl fmt::Debug for MontgomeryXpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.0[..].fmt(formatter)
    }
}

impl ConstantTimeEq for MontgomeryXpoint {
    fn ct_eq(&self, other: &MontgomeryXpoint) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for MontgomeryXpoint {
    fn eq(&self, other: &MontgomeryXpoint) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for MontgomeryXpoint {}

/// A Projective point in Montgomery form
#[derive(Copy, Clone, Debug, Eq)]
pub struct ProjectiveMontgomeryXpoint {
    pub(super) U: FieldElement,
    pub(super) W: FieldElement,
}

impl Mul<&MontgomeryScalar> for &MontgomeryXpoint {
    type Output = ProjectiveMontgomeryXpoint;

    fn mul(self, scalar: &MontgomeryScalar) -> ProjectiveMontgomeryXpoint {
        self.mul_internal(scalar).0
    }
}

impl Mul<&MontgomeryXpoint> for &MontgomeryScalar {
    type Output = ProjectiveMontgomeryXpoint;

    fn mul(self, point: &MontgomeryXpoint) -> ProjectiveMontgomeryXpoint {
        point * self
    }
}

impl MontgomeryXpoint {
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
        (*self == Self::LOW_A) || (*self == Self::LOW_B) || (*self == Self::LOW_C)
    }

    /// View the point as a byte slice
    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.0
    }

    /// Compute the Y-coordinate
    pub fn y(&self, sign: Choice) -> [u8; 56] {
        Self::y_internal(&FieldElement::from_bytes(&self.0), sign).to_bytes()
    }

    // See https://www.rfc-editor.org/rfc/rfc7748#section-1.
    pub(super) fn y_internal(u: &FieldElement, sign: Choice) -> FieldElement {
        // v^2 = u^3 + A*u^2 + u
        let uu = u.square();
        let vv = uu * u + FieldElement::J * uu + u;

        let mut v = vv.sqrt();
        v.conditional_negate(v.is_negative() ^ sign);
        v
    }

    pub(super) fn mul_internal(
        &self,
        scalar: &MontgomeryScalar,
    ) -> (ProjectiveMontgomeryXpoint, ProjectiveMontgomeryXpoint) {
        // Algorithm 8 of Costello-Smith 2017
        let mut x0 = ProjectiveMontgomeryXpoint::IDENTITY;
        let mut x1 = self.to_projective();
        let diff = x1.U;

        let bits = scalar.bits();
        let mut swap = 0;
        for s in (0..448).rev() {
            let bit = bits[s] as u8;
            let choice: u8 = swap ^ bit;

            ProjectiveMontgomeryXpoint::conditional_swap(&mut x0, &mut x1, Choice::from(choice));
            differential_add_and_double(&mut x0, &mut x1, &diff);

            swap = bit;
        }

        (x0, x1)
    }

    /// Convert the point to a ProjectiveMontgomeryPoint
    pub fn to_projective(&self) -> ProjectiveMontgomeryXpoint {
        ProjectiveMontgomeryXpoint {
            U: FieldElement::from_bytes(&self.0),
            W: FieldElement::ONE,
        }
    }

    /// Convert the point to projective form including the y-coordinate
    pub fn to_extended_projective(&self, sign: Choice) -> ProjectiveMontgomeryPoint {
        self.to_projective().to_extended(sign)
    }

    /// Convert the point to its form including the y-coordinate
    pub fn to_extended(&self, sign: Choice) -> MontgomeryPoint {
        let x = FieldElement::from_bytes(&self.0);
        let y = Self::y_internal(&x, sign);

        MontgomeryPoint::new(x, y)
    }
}

impl ConstantTimeEq for ProjectiveMontgomeryXpoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        (self.U * other.W).ct_eq(&(other.U * self.W))
    }
}

impl ConditionallySelectable for ProjectiveMontgomeryXpoint {
    fn conditional_select(
        a: &ProjectiveMontgomeryXpoint,
        b: &ProjectiveMontgomeryXpoint,
        choice: Choice,
    ) -> ProjectiveMontgomeryXpoint {
        ProjectiveMontgomeryXpoint {
            U: FieldElement::conditional_select(&a.U, &b.U, choice),
            W: FieldElement::conditional_select(&a.W, &b.W, choice),
        }
    }
}

impl PartialEq for ProjectiveMontgomeryXpoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Mul<&MontgomeryScalar> for &ProjectiveMontgomeryXpoint {
    type Output = ProjectiveMontgomeryXpoint;

    fn mul(self, scalar: &MontgomeryScalar) -> ProjectiveMontgomeryXpoint {
        &self.to_affine() * scalar
    }
}

impl Mul<&ProjectiveMontgomeryXpoint> for &MontgomeryScalar {
    type Output = ProjectiveMontgomeryXpoint;

    fn mul(self, point: &ProjectiveMontgomeryXpoint) -> ProjectiveMontgomeryXpoint {
        point * self
    }
}

// (1987 Montgomery) Speeding the Pollard and elliptic curve methods of factorization
// fifth and sixth displays, plus common-subexpression elimination, plus assumption Z1=1
fn differential_add_and_double(
    P: &mut ProjectiveMontgomeryXpoint,
    Q: &mut ProjectiveMontgomeryXpoint,
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

impl ProjectiveMontgomeryXpoint {
    /// The identity element of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        U: FieldElement::ONE,
        W: FieldElement::ZERO,
    };

    /// The generator point
    pub const GENERATOR: Self = Self {
        U: FieldElement(ConstMontyType::new(&U448::from_u64(5))),
        W: FieldElement::ONE,
    };

    // See https://www.rfc-editor.org/rfc/rfc7748#section-1.
    fn y(&self, sign: Choice) -> FieldElement {
        // v^2 = u^3 + A*u^2 + u
        let u_sq = self.U.square();
        let v_sq = u_sq * self.U + FieldElement::J * u_sq + self.U;

        let mut v = v_sq.sqrt();
        v.conditional_negate(v.is_negative() ^ sign);
        v
    }

    /// Double this point
    // https://eprint.iacr.org/2020/1338.pdf (2.2)
    pub fn double(&self) -> Self {
        let v1 = (self.U + self.W).square();
        let v2 = (self.U - self.W).square();
        let U = v1 * v2;
        let v3 = v1 - v2;
        let v4 = FieldElement::A_PLUS_TWO_OVER_FOUR * v3;
        let v5 = v2 + v4;
        let W = v3 * v5;

        Self { U, W }
    }

    /// Convert the point to affine form
    pub fn to_affine(&self) -> MontgomeryXpoint {
        let x = self.U * self.W.invert();
        MontgomeryXpoint(x.to_bytes())
    }

    /// Convert the point to affine form including the y-coordinate
    pub fn to_extended_affine(&self, sign: Choice) -> MontgomeryPoint {
        let x = self.U * self.W.invert();
        let y = self.y(sign);

        MontgomeryPoint::new(x, y)
    }

    /// Convert the point to its form including the y-coordinate
    pub fn to_extended(&self, sign: Choice) -> ProjectiveMontgomeryPoint {
        ProjectiveMontgomeryPoint::conditional_select(
            &ProjectiveMontgomeryPoint::new(self.U, self.y(sign), self.W),
            &ProjectiveMontgomeryPoint::IDENTITY,
            self.ct_eq(&Self::IDENTITY),
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_montgomery_edwards() {
        let scalar = MontgomeryScalar::from(200u32);

        // Montgomery scalar mul
        let montgomery_res = &(&ProjectiveMontgomeryXpoint::GENERATOR * &scalar) * &scalar;

        // Goldilocks scalar mul
        let goldilocks_point = EdwardsPoint::GENERATOR * scalar.to_scalar() * scalar.to_scalar();
        assert_eq!(
            goldilocks_point.to_montgomery_x(),
            montgomery_res.to_affine()
        );
    }

    #[test]
    fn to_extended() {
        let x_identity = ProjectiveMontgomeryXpoint::IDENTITY;
        let identity = ProjectiveMontgomeryPoint::IDENTITY;

        assert_eq!(x_identity.to_extended(Choice::from(1)), identity);
    }

    #[test]
    fn to_extended_affine() {
        let x_identity = ProjectiveMontgomeryXpoint::IDENTITY.to_affine();
        let identity = MontgomeryPoint::from(ProjectiveMontgomeryPoint::IDENTITY);

        assert_eq!(x_identity.to_extended(Choice::from(1)), identity);
    }
}
