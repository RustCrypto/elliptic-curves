use crate::field::{ConstMontyType, FieldElement};
use core::borrow::Borrow;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::CurveGroup;
use elliptic_curve::bigint::U448;
use subtle::{Choice, ConditionallySelectable};

use super::{MontgomeryPoint, MontgomeryScalar, ProjectiveMontgomeryPoint};

impl Add<&ProjectiveMontgomeryPoint> for &ProjectiveMontgomeryPoint {
    type Output = ProjectiveMontgomeryPoint;

    // Copied from https://github.com/armfazh/redox-ecc/blob/5a8c09c5ef9fe6a8d2c749d05eca011c6d661599/src/montgomery/point.rs#L80-L104.
    fn add(self, rhs: &ProjectiveMontgomeryPoint) -> Self::Output {
        const S: FieldElement = FieldElement(ConstMontyType::new(&U448::from_u64(3)));

        let (x1, y1, z1) = (self.U, self.V, self.W);
        let (x2, y2, z2) = (rhs.U, rhs.V, rhs.W);
        let (a_ec, s_ec) = (FieldElement::J, S);
        let (t0, t1, t2) = (x1 * x2, y1 * y2, z1 * z2);
        let (t3, t4) = (x1 * y2, x2 * y1);
        let (t5, t6) = (y1 * z2, y2 * z1);
        let (t7, t8) = (x1 * z2, x2 * z1);
        let t9 = t7 + t8;
        let ta = t9 + (t0 * a_ec);
        let rr = t5 + t6;
        let tt = ta - t1;
        let vv = t9 * a_ec + t0.double() + t0 + t2;
        let ss = (t3 - t4) * s_ec + t0 - t2;
        let uu = (t7 - t8) * s_ec - t3 - t4;
        let ww = (t5 - t6) * s_ec + ta + t1;
        let x3 = rr * ss - tt * uu;
        let y3 = tt * ww - vv * ss;
        let z3 = vv * uu - rr * ww;

        ProjectiveMontgomeryPoint {
            U: x3,
            V: y3,
            W: z3,
        }
    }
}

define_add_variants!(
    LHS = ProjectiveMontgomeryPoint,
    RHS = ProjectiveMontgomeryPoint,
    Output = ProjectiveMontgomeryPoint
);

impl Add<&MontgomeryPoint> for &ProjectiveMontgomeryPoint {
    type Output = ProjectiveMontgomeryPoint;

    fn add(self, other: &MontgomeryPoint) -> ProjectiveMontgomeryPoint {
        *self + *other
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
        *other + *self
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

        for s in (0..448).rev() {
            p = p + p;
            p.conditional_assign(&(p + self), Choice::from(bits[s] as u8));
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
