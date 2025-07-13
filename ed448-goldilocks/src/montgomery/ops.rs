use crate::field::FieldElement;
use core::borrow::Borrow;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::CurveGroup;
use subtle::{Choice, ConditionallySelectable};

use super::{MontgomeryPoint, MontgomeryScalar, ProjectiveMontgomeryPoint};

impl Add<&ProjectiveMontgomeryPoint> for &ProjectiveMontgomeryPoint {
    type Output = ProjectiveMontgomeryPoint;

    // See Complete Addition Law for Montgomery Curves - Algorithm 1.
    // With "Trade-Off Technique".
    fn add(self, rhs: &ProjectiveMontgomeryPoint) -> Self::Output {
        let (x1, y1, z1) = (self.U, self.V, self.W);
        let (x2, y2, z2) = (rhs.U, rhs.V, rhs.W);

        let t0 = x1 * x2;
        let t1 = y1 * y2;
        let t2 = z1 * z2;
        let t3 = x1 * y2;
        let t4 = x2 * y1;
        let t5 = y1 * z2;
        let t6 = y2 * z1;
        let t7 = x1 * z2;
        let t8 = x2 * z1;
        let t9 = t7 + t8;
        let t10 = t9 + FieldElement::J * t0;
        let R = t5 + t6;
        let T = t10 - t1;
        let V = FieldElement::J * t9 + t0.triple() + t2;
        let S = (t3 - t4).triple() + t0 - t2;
        let U = (t7 - t8).triple() - t3 - t4;
        let W = (t5 - t6).triple() + t10 + t1;
        let C = (R + T) * (S - U);
        let D = (R - T) * (S + U);
        let E = (T + V) * (W - S);
        let F = (T - V) * (W + S);
        let X = C + D;
        let Y = E + F;
        let Z = (U - W).double() * (R + V) + C - D + E - F;

        ProjectiveMontgomeryPoint { U: X, V: Y, W: Z }
    }
}

define_add_variants!(
    LHS = ProjectiveMontgomeryPoint,
    RHS = ProjectiveMontgomeryPoint,
    Output = ProjectiveMontgomeryPoint
);

impl Add<&MontgomeryPoint> for &ProjectiveMontgomeryPoint {
    type Output = ProjectiveMontgomeryPoint;

    // See Complete Addition Law for Montgomery Curves - Algorithm 1.
    // With "Trade-Off Technique".
    fn add(self, rhs: &MontgomeryPoint) -> ProjectiveMontgomeryPoint {
        let (x1, y1, z1) = (self.U, self.V, self.W);
        let (x2, y2) = (rhs.x, rhs.y);

        let t0 = x1 * x2;
        let t1 = y1 * y2;
        let t2 = z1;
        let t3 = x1 * y2;
        let t4 = x2 * y1;
        let t5 = y1;
        let t6 = y2 * z1;
        let t7 = x1;
        let t8 = x2 * z1;
        let t9 = t7 + t8;
        let t10 = t9 + FieldElement::J * t0;
        let R = t5 + t6;
        let T = t10 - t1;
        let V = FieldElement::J * t9 + t0.triple() + t2;
        let S = (t3 - t4).triple() + t0 - t2;
        let U = (t7 - t8).triple() - t3 - t4;
        let W = (t5 - t6).triple() + t10 + t1;
        let C = (R + T) * (S - U);
        let D = (R - T) * (S + U);
        let E = (T + V) * (W - S);
        let F = (T - V) * (W + S);
        let X = C + D;
        let Y = E + F;
        let Z = (U - W).double() * (R + V) + C - D + E - F;

        ProjectiveMontgomeryPoint { U: X, V: Y, W: Z }
    }
}

define_add_variants!(
    LHS = ProjectiveMontgomeryPoint,
    RHS = MontgomeryPoint,
    Output = ProjectiveMontgomeryPoint
);

impl Add<&ProjectiveMontgomeryPoint> for &MontgomeryPoint {
    type Output = ProjectiveMontgomeryPoint;

    fn add(self, other: &ProjectiveMontgomeryPoint) -> ProjectiveMontgomeryPoint {
        other + self
    }
}

define_add_variants!(
    LHS = MontgomeryPoint,
    RHS = ProjectiveMontgomeryPoint,
    Output = ProjectiveMontgomeryPoint
);

impl<'b> AddAssign<&'b ProjectiveMontgomeryPoint> for ProjectiveMontgomeryPoint {
    fn add_assign(&mut self, rhs: &'b Self) {
        *self = *self + rhs;
    }
}

define_add_assign_variants!(
    LHS = ProjectiveMontgomeryPoint,
    RHS = ProjectiveMontgomeryPoint
);

impl AddAssign<&MontgomeryPoint> for ProjectiveMontgomeryPoint {
    fn add_assign(&mut self, rhs: &MontgomeryPoint) {
        *self += Self::from(*rhs);
    }
}

define_add_assign_variants!(LHS = ProjectiveMontgomeryPoint, RHS = MontgomeryPoint);

impl AddAssign<&ProjectiveMontgomeryPoint> for MontgomeryPoint {
    fn add_assign(&mut self, rhs: &ProjectiveMontgomeryPoint) {
        *self = (ProjectiveMontgomeryPoint::from(*self) + rhs).to_affine();
    }
}

define_add_assign_variants!(LHS = MontgomeryPoint, RHS = ProjectiveMontgomeryPoint);

impl Mul<&MontgomeryScalar> for &ProjectiveMontgomeryPoint {
    type Output = ProjectiveMontgomeryPoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, scalar: &MontgomeryScalar) -> ProjectiveMontgomeryPoint {
        let mut p = ProjectiveMontgomeryPoint::IDENTITY;
        let bits = scalar.bits();

        for index in (0..448).rev() {
            p = p + p;
            p.conditional_assign(&(p + self), Choice::from(bits[index] as u8));
        }

        p
    }
}

define_mul_variants!(
    LHS = ProjectiveMontgomeryPoint,
    RHS = MontgomeryScalar,
    Output = ProjectiveMontgomeryPoint
);

impl Mul<&MontgomeryPoint> for &MontgomeryScalar {
    type Output = ProjectiveMontgomeryPoint;

    #[inline]
    fn mul(self, point: &MontgomeryPoint) -> ProjectiveMontgomeryPoint {
        ProjectiveMontgomeryPoint::from(*point) * self
    }
}

define_mul_variants!(
    LHS = MontgomeryScalar,
    RHS = MontgomeryPoint,
    Output = ProjectiveMontgomeryPoint
);

impl Mul<&ProjectiveMontgomeryPoint> for &MontgomeryScalar {
    type Output = ProjectiveMontgomeryPoint;

    fn mul(self, point: &ProjectiveMontgomeryPoint) -> ProjectiveMontgomeryPoint {
        point * self
    }
}

define_mul_variants!(
    LHS = MontgomeryScalar,
    RHS = ProjectiveMontgomeryPoint,
    Output = ProjectiveMontgomeryPoint
);

impl<'b> MulAssign<&'b MontgomeryScalar> for ProjectiveMontgomeryPoint {
    fn mul_assign(&mut self, scalar: &'b MontgomeryScalar) {
        let result = *self * scalar;
        *self = result;
    }
}

define_mul_assign_variants!(LHS = ProjectiveMontgomeryPoint, RHS = MontgomeryScalar);

impl Neg for &ProjectiveMontgomeryPoint {
    type Output = ProjectiveMontgomeryPoint;

    fn neg(self) -> ProjectiveMontgomeryPoint {
        ProjectiveMontgomeryPoint {
            U: self.U,
            V: -self.V,
            W: self.W,
        }
    }
}

impl Neg for ProjectiveMontgomeryPoint {
    type Output = Self;

    fn neg(self) -> Self {
        -&self
    }
}

impl Sub<&ProjectiveMontgomeryPoint> for &ProjectiveMontgomeryPoint {
    type Output = ProjectiveMontgomeryPoint;

    fn sub(self, other: &ProjectiveMontgomeryPoint) -> ProjectiveMontgomeryPoint {
        self.add(&other.neg())
    }
}

define_sub_variants!(
    LHS = ProjectiveMontgomeryPoint,
    RHS = ProjectiveMontgomeryPoint,
    Output = ProjectiveMontgomeryPoint
);

impl Sub<&MontgomeryPoint> for &ProjectiveMontgomeryPoint {
    type Output = ProjectiveMontgomeryPoint;

    fn sub(self, other: &MontgomeryPoint) -> ProjectiveMontgomeryPoint {
        *self - ProjectiveMontgomeryPoint::from(*other)
    }
}

define_sub_variants!(
    LHS = ProjectiveMontgomeryPoint,
    RHS = MontgomeryPoint,
    Output = ProjectiveMontgomeryPoint
);

impl Sub<&ProjectiveMontgomeryPoint> for &MontgomeryPoint {
    type Output = ProjectiveMontgomeryPoint;

    fn sub(self, other: &ProjectiveMontgomeryPoint) -> ProjectiveMontgomeryPoint {
        *self - other
    }
}

define_sub_variants!(
    LHS = MontgomeryPoint,
    RHS = ProjectiveMontgomeryPoint,
    Output = ProjectiveMontgomeryPoint
);

impl<'b> SubAssign<&'b Self> for ProjectiveMontgomeryPoint {
    fn sub_assign(&mut self, _rhs: &'b Self) {
        *self = *self - _rhs;
    }
}

define_sub_assign_variants!(
    LHS = ProjectiveMontgomeryPoint,
    RHS = ProjectiveMontgomeryPoint
);

impl SubAssign<&MontgomeryPoint> for ProjectiveMontgomeryPoint {
    fn sub_assign(&mut self, rhs: &MontgomeryPoint) {
        *self -= ProjectiveMontgomeryPoint::from(*rhs);
    }
}

define_sub_assign_variants!(LHS = ProjectiveMontgomeryPoint, RHS = MontgomeryPoint);

impl SubAssign<&ProjectiveMontgomeryPoint> for MontgomeryPoint {
    fn sub_assign(&mut self, rhs: &ProjectiveMontgomeryPoint) {
        *self = (ProjectiveMontgomeryPoint::from(*self) - rhs).to_affine();
    }
}

define_sub_assign_variants!(LHS = MontgomeryPoint, RHS = ProjectiveMontgomeryPoint);

impl<T> Sum<T> for ProjectiveMontgomeryPoint
where
    T: Borrow<Self>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::IDENTITY, |acc, item| acc + item.borrow())
    }
}

#[cfg(test)]
mod test {
    use elliptic_curve::Group;
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn mixed_addition() {
        let p1 = ProjectiveMontgomeryPoint::try_from_rng(&mut OsRng).unwrap();
        let p2 = ProjectiveMontgomeryPoint::try_from_rng(&mut OsRng).unwrap();
        let p3 = p1 + p2;

        assert_eq!(p3.to_affine(), (p1.to_affine() + p2).to_affine());
    }
}
