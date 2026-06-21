//! Scalar multiplication backends.

#[cfg(feature = "basepoint-table")]
mod precomputed_tables;
mod variable_only;

use crate::{PrimeCurveParams, ProjectivePoint};
use elliptic_curve::Scalar;
use elliptic_curve::ops::LinearCombination;

#[cfg(feature = "basepoint-table")]
pub use self::precomputed_tables::PrecomputedTables;
pub use self::variable_only::VariableOnly;

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
