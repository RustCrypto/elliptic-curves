//! Scalar multiplication backends.

use crate::{PrimeCurveParams, ProjectivePoint};
use elliptic_curve::Scalar;
use elliptic_curve::ops::LinearCombination;

#[cfg(feature = "basepoint-table")]
use crate::PrimeCurveWithBasepointTable;

/// Scalar multiplication backend.
pub trait MulBackend<C: PrimeCurveParams> {
    /// Multiplication by the generator.
    ///
    /// This is overridable to make it possible to plug in a basepoint table.
    #[inline]
    fn mul_by_generator(k: &Scalar<C>) -> ProjectivePoint<C> {
        ProjectivePoint::GENERATOR * k
    }

    /// Variable-time multiplication by the generator.
    ///
    /// This is overridable to make it possible to plug in a basepoint table.
    #[inline]
    fn mul_by_generator_vartime(k: &Scalar<C>) -> ProjectivePoint<C> {
        ProjectivePoint::GENERATOR.mul_vartime(k)
    }

    /// Multiply `a` by the generator of the prime-order subgroup, adding the result to the point
    /// `P` multiplied by the scalar `b`, i.e. compute `aG + bP`.
    #[inline]
    fn mul_by_generator_and_mul_add_vartime(
        a: &Scalar<C>,
        b_scalar: &Scalar<C>,
        b_point: &ProjectivePoint<C>,
    ) -> ProjectivePoint<C> {
        ProjectivePoint::<C>::lincomb_vartime(&[
            (ProjectivePoint::GENERATOR, *a),
            (*b_point, *b_scalar),
        ])
    }
}

/// Simple backend that only supports variable-base scalar multiplication.
#[derive(Clone, Copy, Debug)]
pub struct VariableOnly;

impl<C: PrimeCurveParams> MulBackend<C> for VariableOnly {}

/// Backend based on precomputed tables.
#[derive(Clone, Copy, Debug)]
#[cfg(feature = "basepoint-table")]
pub struct PrecomputedTables<const WINDOW_SIZE: usize>;

#[cfg(feature = "basepoint-table")]
impl<C, const WINDOW_SIZE: usize> MulBackend<C> for PrecomputedTables<WINDOW_SIZE>
where
    C: PrimeCurveParams + PrimeCurveWithBasepointTable<WINDOW_SIZE>,
{
    #[inline]
    fn mul_by_generator(k: &Scalar<C>) -> ProjectivePoint<C> {
        C::BASEPOINT_TABLE.mul(k)
    }

    #[inline]
    fn mul_by_generator_vartime(k: &Scalar<C>) -> ProjectivePoint<C> {
        C::BASEPOINT_TABLE.mul_vartime(k)
    }
}
