//! Precomputed tables (optional).

use super::NistP384;
use crate::ProjectivePoint;
use primeorder::PrimeCurveWithBasepointTable;

/// Window size for the basepoint table (1 + 48-byte modulus)
pub(super) const WINDOW_SIZE: usize = 49;

/// Basepoint table for multiples of NIST P-384's generator.
pub(super) type BasepointTable = primeorder::BasepointTable<ProjectivePoint, WINDOW_SIZE>;

/// Lazily computed basepoint table.
pub(super) static BASEPOINT_TABLE: BasepointTable = BasepointTable::new();

impl PrimeCurveWithBasepointTable<WINDOW_SIZE> for NistP384 {
    const BASEPOINT_TABLE: &'static BasepointTable = &BASEPOINT_TABLE;
}

/// Workaround for rust-lang/rust#140653 to support MSRV 1.85: we can't use the generic
/// implementation in `primeorder::mul_backend::PrecomputedTables` until MSRV 1.90 due to restrictions
/// on referencing a type with interior mutability from a `const`.
// TODO(tarcieri): remove this and switch to `primeorder::mul_backend::PrecomputedTables` when MSRV 1.90
pub(crate) mod backend {
    use super::BASEPOINT_TABLE;
    use crate::{NistP384, ProjectivePoint, Scalar};
    use primeorder::MulBackend;

    /// Backend based on precomputed tables.
    pub struct PrecomputedTables;

    impl MulBackend<NistP384> for PrecomputedTables {
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
