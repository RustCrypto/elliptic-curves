use core::ops::{Mul, MulAssign};
use elliptic_curve::{
    subtle::{ConditionallySelectable, ConstantTimeEq},
};

use crate::arithmetic::ProjectivePoint;
use crate::arithmetic::scalar::Scalar;

/// Returns `[k] x`.
fn mul_window(x: &ProjectivePoint, k: &Scalar) -> ProjectivePoint {
    const LOG_MUL_WINDOW_SIZE: usize = 4;
    const MUL_STEPS: usize = (256 - 1) / LOG_MUL_WINDOW_SIZE + 1;
    const MUL_PRECOMP_SIZE: usize = 1 << LOG_MUL_WINDOW_SIZE;

    let mut precomp = [ProjectivePoint::identity(); MUL_PRECOMP_SIZE];
    let mask = (1u32 << LOG_MUL_WINDOW_SIZE) - 1u32;

    precomp[0] = ProjectivePoint::identity();
    precomp[1] = *x;
    for i in 2..MUL_PRECOMP_SIZE {
        precomp[i] = precomp[i - 1] + x;
    }

    let mut acc = ProjectivePoint::identity();
    for idx in (0..MUL_STEPS).rev() {
        for _j in 0..LOG_MUL_WINDOW_SIZE {
            acc = acc.double();
        }
        let di = ((k >> (idx * LOG_MUL_WINDOW_SIZE)).truncate_to_u32() & mask) as usize;

        // Constant-time array indexing
        let mut elem = ProjectivePoint::identity();
        for i in 0..MUL_PRECOMP_SIZE {
            elem = ProjectivePoint::conditional_select(&elem, &(precomp[di]), i.ct_eq(&di));
        }

        acc += precomp[di as usize];
    }

    acc
}

impl Mul<&Scalar> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        mul_window(self, other)
    }
}

impl Mul<&Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        mul_window(&self, other)
    }
}

impl MulAssign<Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = mul_window(self, &rhs);
    }
}

impl MulAssign<&Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = mul_window(self, rhs);
    }
}
