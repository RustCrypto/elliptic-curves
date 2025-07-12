use crate::field::{ConstMontyType, FieldElement};
use core::borrow::Borrow;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::CurveGroup;
use elliptic_curve::bigint::U448;
use subtle::{Choice, ConditionallySelectable};

use super::{ExtendedMontgomeryPoint, ExtendedProjectiveMontgomeryPoint, MontgomeryScalar};

impl Add<&ExtendedProjectiveMontgomeryPoint> for &ExtendedProjectiveMontgomeryPoint {
    type Output = ExtendedProjectiveMontgomeryPoint;

    // Copied from https://github.com/armfazh/redox-ecc/blob/5a8c09c5ef9fe6a8d2c749d05eca011c6d661599/src/montgomery/point.rs#L80-L104.
    fn add(self, rhs: &ExtendedProjectiveMontgomeryPoint) -> Self::Output {
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

        ExtendedProjectiveMontgomeryPoint {
            U: x3,
            V: y3,
            W: z3,
        }
    }
}

define_add_variants!(
    LHS = ExtendedProjectiveMontgomeryPoint,
    RHS = ExtendedProjectiveMontgomeryPoint,
    Output = ExtendedProjectiveMontgomeryPoint
);

impl Add<&ExtendedMontgomeryPoint> for &ExtendedProjectiveMontgomeryPoint {
    type Output = ExtendedProjectiveMontgomeryPoint;

    fn add(self, other: &ExtendedMontgomeryPoint) -> ExtendedProjectiveMontgomeryPoint {
        *self + *other
    }
}

define_add_variants!(
    LHS = ExtendedProjectiveMontgomeryPoint,
    RHS = ExtendedMontgomeryPoint,
    Output = ExtendedProjectiveMontgomeryPoint
);

impl Add<&ExtendedProjectiveMontgomeryPoint> for &ExtendedMontgomeryPoint {
    type Output = ExtendedProjectiveMontgomeryPoint;

    fn add(self, other: &ExtendedProjectiveMontgomeryPoint) -> ExtendedProjectiveMontgomeryPoint {
        *other + *self
    }
}

define_add_variants!(
    LHS = ExtendedMontgomeryPoint,
    RHS = ExtendedProjectiveMontgomeryPoint,
    Output = ExtendedProjectiveMontgomeryPoint
);

impl<'b> AddAssign<&'b ExtendedProjectiveMontgomeryPoint> for ExtendedProjectiveMontgomeryPoint {
    fn add_assign(&mut self, rhs: &'b Self) {
        *self = *self + rhs;
    }
}

define_add_assign_variants!(
    LHS = ExtendedProjectiveMontgomeryPoint,
    RHS = ExtendedProjectiveMontgomeryPoint
);

impl AddAssign<&ExtendedMontgomeryPoint> for ExtendedProjectiveMontgomeryPoint {
    fn add_assign(&mut self, rhs: &ExtendedMontgomeryPoint) {
        *self += Self::from(*rhs);
    }
}

define_add_assign_variants!(
    LHS = ExtendedProjectiveMontgomeryPoint,
    RHS = ExtendedMontgomeryPoint
);

impl AddAssign<&ExtendedProjectiveMontgomeryPoint> for ExtendedMontgomeryPoint {
    fn add_assign(&mut self, rhs: &ExtendedProjectiveMontgomeryPoint) {
        *self = (ExtendedProjectiveMontgomeryPoint::from(*self) + rhs).to_affine();
    }
}

define_add_assign_variants!(
    LHS = ExtendedMontgomeryPoint,
    RHS = ExtendedProjectiveMontgomeryPoint
);

impl Mul<&MontgomeryScalar> for &ExtendedProjectiveMontgomeryPoint {
    type Output = ExtendedProjectiveMontgomeryPoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, scalar: &MontgomeryScalar) -> ExtendedProjectiveMontgomeryPoint {
        let mut p = ExtendedProjectiveMontgomeryPoint::IDENTITY;
        let bits = scalar.bits();

        for s in (0..448).rev() {
            p = p + p;
            p.conditional_assign(&(p + self), Choice::from(bits[s] as u8));
        }

        p
    }
}

define_mul_variants!(
    LHS = ExtendedProjectiveMontgomeryPoint,
    RHS = MontgomeryScalar,
    Output = ExtendedProjectiveMontgomeryPoint
);

impl Mul<&ExtendedMontgomeryPoint> for &MontgomeryScalar {
    type Output = ExtendedProjectiveMontgomeryPoint;

    #[inline]
    fn mul(self, point: &ExtendedMontgomeryPoint) -> ExtendedProjectiveMontgomeryPoint {
        ExtendedProjectiveMontgomeryPoint::from(*point) * self
    }
}

define_mul_variants!(
    LHS = MontgomeryScalar,
    RHS = ExtendedMontgomeryPoint,
    Output = ExtendedProjectiveMontgomeryPoint
);

impl Mul<&ExtendedProjectiveMontgomeryPoint> for &MontgomeryScalar {
    type Output = ExtendedProjectiveMontgomeryPoint;

    fn mul(self, point: &ExtendedProjectiveMontgomeryPoint) -> ExtendedProjectiveMontgomeryPoint {
        point * self
    }
}

define_mul_variants!(
    LHS = MontgomeryScalar,
    RHS = ExtendedProjectiveMontgomeryPoint,
    Output = ExtendedProjectiveMontgomeryPoint
);

impl<'b> MulAssign<&'b MontgomeryScalar> for ExtendedProjectiveMontgomeryPoint {
    fn mul_assign(&mut self, scalar: &'b MontgomeryScalar) {
        let result = *self * scalar;
        *self = result;
    }
}

define_mul_assign_variants!(
    LHS = ExtendedProjectiveMontgomeryPoint,
    RHS = MontgomeryScalar
);

impl Neg for &ExtendedProjectiveMontgomeryPoint {
    type Output = ExtendedProjectiveMontgomeryPoint;

    fn neg(self) -> ExtendedProjectiveMontgomeryPoint {
        ExtendedProjectiveMontgomeryPoint {
            U: self.U,
            V: -self.V,
            W: self.W,
        }
    }
}

impl Neg for ExtendedProjectiveMontgomeryPoint {
    type Output = Self;

    fn neg(self) -> Self {
        -&self
    }
}

impl Sub<&ExtendedProjectiveMontgomeryPoint> for &ExtendedProjectiveMontgomeryPoint {
    type Output = ExtendedProjectiveMontgomeryPoint;

    fn sub(self, other: &ExtendedProjectiveMontgomeryPoint) -> ExtendedProjectiveMontgomeryPoint {
        self.add(&other.neg())
    }
}

define_sub_variants!(
    LHS = ExtendedProjectiveMontgomeryPoint,
    RHS = ExtendedProjectiveMontgomeryPoint,
    Output = ExtendedProjectiveMontgomeryPoint
);

impl Sub<&ExtendedMontgomeryPoint> for &ExtendedProjectiveMontgomeryPoint {
    type Output = ExtendedProjectiveMontgomeryPoint;

    fn sub(self, other: &ExtendedMontgomeryPoint) -> ExtendedProjectiveMontgomeryPoint {
        *self - ExtendedProjectiveMontgomeryPoint::from(*other)
    }
}

define_sub_variants!(
    LHS = ExtendedProjectiveMontgomeryPoint,
    RHS = ExtendedMontgomeryPoint,
    Output = ExtendedProjectiveMontgomeryPoint
);

impl Sub<&ExtendedProjectiveMontgomeryPoint> for &ExtendedMontgomeryPoint {
    type Output = ExtendedProjectiveMontgomeryPoint;

    fn sub(self, other: &ExtendedProjectiveMontgomeryPoint) -> ExtendedProjectiveMontgomeryPoint {
        *self - other
    }
}

define_sub_variants!(
    LHS = ExtendedMontgomeryPoint,
    RHS = ExtendedProjectiveMontgomeryPoint,
    Output = ExtendedProjectiveMontgomeryPoint
);

impl<'b> SubAssign<&'b Self> for ExtendedProjectiveMontgomeryPoint {
    fn sub_assign(&mut self, _rhs: &'b Self) {
        *self = *self - _rhs;
    }
}

define_sub_assign_variants!(
    LHS = ExtendedProjectiveMontgomeryPoint,
    RHS = ExtendedProjectiveMontgomeryPoint
);

impl SubAssign<&ExtendedMontgomeryPoint> for ExtendedProjectiveMontgomeryPoint {
    fn sub_assign(&mut self, rhs: &ExtendedMontgomeryPoint) {
        *self -= ExtendedProjectiveMontgomeryPoint::from(*rhs);
    }
}

define_sub_assign_variants!(
    LHS = ExtendedProjectiveMontgomeryPoint,
    RHS = ExtendedMontgomeryPoint
);

impl SubAssign<&ExtendedProjectiveMontgomeryPoint> for ExtendedMontgomeryPoint {
    fn sub_assign(&mut self, rhs: &ExtendedProjectiveMontgomeryPoint) {
        *self = (ExtendedProjectiveMontgomeryPoint::from(*self) - rhs).to_affine();
    }
}

define_sub_assign_variants!(
    LHS = ExtendedMontgomeryPoint,
    RHS = ExtendedProjectiveMontgomeryPoint
);

impl<T> Sum<T> for ExtendedProjectiveMontgomeryPoint
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
