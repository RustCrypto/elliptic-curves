//! Precomputed tables (optional).

use super::BignP256;
use crate::ProjectivePoint;
use primeorder::PrimeCurveWithBasepointTable;

/// Window size for the basepoint table (1 + 32-byte modulus)
pub(super) const WINDOW_SIZE: usize = 33;

/// Basepoint table for multiples of bign-curve256v1's generator.
pub(super) type BasepointTable = primeorder::BasepointTable<ProjectivePoint, WINDOW_SIZE>;

/// Lazily computed basepoint table.
pub(super) static BASEPOINT_TABLE: BasepointTable = BasepointTable::new();

impl PrimeCurveWithBasepointTable<WINDOW_SIZE> for BignP256 {
    const BASEPOINT_TABLE: &'static BasepointTable = &BASEPOINT_TABLE;
}

/// Workaround for rust-lang/rust#140653 to support MSRV 1.85, mirroring `p256`: we can't use
/// `primeorder::mul_backend::PrecomputedTables` until MSRV 1.90.
// TODO(tarcieri): remove this and switch to `primeorder::mul_backend::PrecomputedTables` when MSRV 1.90
pub(crate) mod backend {
    use super::BASEPOINT_TABLE;
    use crate::{BignP256, ProjectivePoint, Scalar};
    use primeorder::MulBackend;

    /// Backend based on precomputed tables.
    #[derive(Clone, Copy, Debug)]
    pub struct PrecomputedTables;

    impl MulBackend<BignP256> for PrecomputedTables {
        #[inline]
        fn mul_by_generator(k: &Scalar) -> ProjectivePoint {
            BASEPOINT_TABLE.mul(k)
        }

        #[inline]
        fn mul_by_generator_vartime(k: &Scalar) -> ProjectivePoint {
            BASEPOINT_TABLE.mul_vartime(k)
        }
    }
}
