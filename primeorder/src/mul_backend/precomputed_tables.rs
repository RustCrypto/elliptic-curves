use super::MulBackend;
use crate::{PrimeCurveParams, PrimeCurveWithBasepointTable, ProjectivePoint};
use elliptic_curve::Scalar;

/// Backend based on precomputed tables.
pub struct PrecomputedTables<const WINDOW_SIZE: usize>;

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
