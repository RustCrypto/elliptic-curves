use crate::{curve::scalar_mul::double_and_add, DecafAffinePoint, Scalar};
use core::{
    borrow::Borrow,
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::group::Curve;

use super::DecafPoint;

/// Scalar Mul Operations
impl Mul<&Scalar> for &DecafPoint {
    type Output = DecafPoint;

    fn mul(self, scalar: &Scalar) -> DecafPoint {
        // XXX: We can do better than double and add
        DecafPoint(double_and_add(&self.0, scalar))
    }
}

define_mul_variants!(LHS = DecafPoint, RHS = Scalar, Output = DecafPoint);

impl Mul<&DecafPoint> for &Scalar {
    type Output = DecafPoint;

    fn mul(self, point: &DecafPoint) -> DecafPoint {
        point * self
    }
}

define_mul_variants!(LHS = Scalar, RHS = DecafPoint, Output = DecafPoint);

impl<'s> MulAssign<&'s Scalar> for DecafPoint {
    fn mul_assign(&mut self, scalar: &'s Scalar) {
        *self = *self * scalar;
    }
}
impl MulAssign<Scalar> for DecafPoint {
    fn mul_assign(&mut self, scalar: Scalar) {
        *self = *self * scalar;
    }
}

// Point addition

impl Add<&DecafPoint> for &DecafPoint {
    type Output = DecafPoint;

    fn add(self, other: &DecafPoint) -> DecafPoint {
        DecafPoint(self.0.to_extensible().add_extended(&other.0).to_extended())
    }
}

impl Add<&DecafAffinePoint> for &DecafPoint {
    type Output = DecafPoint;

    fn add(self, rhs: &DecafAffinePoint) -> Self::Output {
        self + DecafPoint(rhs.0.to_extended())
    }
}

impl Add<&DecafPoint> for &DecafAffinePoint {
    type Output = DecafPoint;

    fn add(self, rhs: &DecafPoint) -> Self::Output {
        DecafPoint(self.0.to_extended()) + rhs
    }
}

define_add_variants!(LHS = DecafPoint, RHS = DecafPoint, Output = DecafPoint);
define_add_variants!(
    LHS = DecafPoint,
    RHS = DecafAffinePoint,
    Output = DecafPoint
);
define_add_variants!(
    LHS = DecafAffinePoint,
    RHS = DecafPoint,
    Output = DecafPoint
);

impl AddAssign<&DecafPoint> for DecafPoint {
    fn add_assign(&mut self, other: &DecafPoint) {
        *self = *self + other;
    }
}
impl AddAssign for DecafPoint {
    fn add_assign(&mut self, other: DecafPoint) {
        *self = *self + other;
    }
}

impl AddAssign<&DecafAffinePoint> for DecafPoint {
    fn add_assign(&mut self, other: &DecafAffinePoint) {
        *self = *self + *other;
    }
}

impl AddAssign<&DecafPoint> for DecafAffinePoint {
    fn add_assign(&mut self, rhs: &DecafPoint) {
        *self = (DecafPoint(self.0.to_extended()) + rhs).to_affine();
    }
}

define_add_assign_variants!(LHS = DecafPoint, RHS = DecafAffinePoint);
define_add_assign_variants!(LHS = DecafAffinePoint, RHS = DecafPoint);

// Point Subtraction

impl Sub<&DecafPoint> for &DecafPoint {
    type Output = DecafPoint;

    fn sub(self, other: &DecafPoint) -> DecafPoint {
        DecafPoint(self.0.to_extensible().sub_extended(&other.0).to_extended())
    }
}

impl Sub<&DecafAffinePoint> for &DecafPoint {
    type Output = DecafPoint;

    fn sub(self, rhs: &DecafAffinePoint) -> Self::Output {
        self - DecafPoint(rhs.0.to_extended())
    }
}

impl Sub<&DecafPoint> for &DecafAffinePoint {
    type Output = DecafPoint;

    fn sub(self, rhs: &DecafPoint) -> Self::Output {
        DecafPoint(self.0.to_extended()) - rhs
    }
}

define_sub_variants!(LHS = DecafPoint, RHS = DecafPoint, Output = DecafPoint);
define_sub_variants!(
    LHS = DecafPoint,
    RHS = DecafAffinePoint,
    Output = DecafPoint
);
define_sub_variants!(
    LHS = DecafAffinePoint,
    RHS = DecafPoint,
    Output = DecafPoint
);

impl SubAssign<&DecafPoint> for DecafPoint {
    fn sub_assign(&mut self, other: &DecafPoint) {
        *self = *self - other;
    }
}
impl SubAssign for DecafPoint {
    fn sub_assign(&mut self, other: DecafPoint) {
        *self = *self - other;
    }
}

impl SubAssign<&DecafAffinePoint> for DecafPoint {
    fn sub_assign(&mut self, other: &DecafAffinePoint) {
        *self = *self - *other;
    }
}

impl SubAssign<&DecafPoint> for DecafAffinePoint {
    fn sub_assign(&mut self, rhs: &DecafPoint) {
        *self = (DecafPoint(self.0.to_extended()) - rhs).to_affine();
    }
}

define_sub_assign_variants!(LHS = DecafPoint, RHS = DecafAffinePoint);
define_sub_assign_variants!(LHS = DecafAffinePoint, RHS = DecafPoint);

// Point Negation

impl Neg for &DecafPoint {
    type Output = DecafPoint;

    fn neg(self) -> DecafPoint {
        DecafPoint(self.0.negate())
    }
}
impl Neg for DecafPoint {
    type Output = DecafPoint;

    fn neg(self) -> DecafPoint {
        (&self).neg()
    }
}

impl<T> Sum<T> for DecafPoint
where
    T: Borrow<DecafPoint>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::IDENTITY, |acc, item| acc + item.borrow())
    }
}
