//! Precomputed tables (optional).

use super::NistP521;
use crate::ProjectivePoint;
use primeorder::PrimeCurveWithBasepointTable;

#[cfg(feature = "alloc")]
pub(super) use vartime::BASEPOINT_TABLE_VARTIME;

/// Window size for the basepoint table.
const WINDOW_SIZE: usize = 67;

/// Basepoint table for multiples of NIST P-521's generator.
type BasepointTable = primeorder::BasepointTable<ProjectivePoint, WINDOW_SIZE>;

/// Lazily computed basepoint table.
pub(super) static BASEPOINT_TABLE: BasepointTable = BasepointTable::new();

impl PrimeCurveWithBasepointTable<WINDOW_SIZE> for NistP521 {
    const BASEPOINT_TABLE: &'static BasepointTable = &BASEPOINT_TABLE;
}

#[cfg(feature = "alloc")]
mod vartime {
    use crate::{NistP521, ProjectivePoint};
    use primeorder::PrimeCurveWithBasepointTableVartime;

    /// Window size for the variable-time basepoint table.
    const WINDOW_SIZE_VARTIME: usize = 8;

    /// Variable-time basepoint table for NIST P-521's generator.
    type BasepointTableVartime =
        primeorder::BasepointTableVartime<ProjectivePoint, WINDOW_SIZE_VARTIME>;

    /// Lazily computed basepoint table.
    pub(crate) static BASEPOINT_TABLE_VARTIME: BasepointTableVartime = BasepointTableVartime::new();

    impl PrimeCurveWithBasepointTableVartime<WINDOW_SIZE_VARTIME> for NistP521 {
        const BASEPOINT_TABLE_VARTIME: &'static BasepointTableVartime = &BASEPOINT_TABLE_VARTIME;
    }
}
