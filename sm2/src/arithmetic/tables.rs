//! Precomputed tables (optional).

#[cfg(feature = "alloc")]
pub(super) use vartime::BASEPOINT_TABLE_VARTIME;

#[cfg(feature = "alloc")]
mod vartime {
    use crate::{ProjectivePoint, Sm2};
    use primeorder::PrimeCurveWithBasepointTableVartime;

    /// Window size for the variable-time basepoint table.
    const WINDOW_SIZE_VARTIME: usize = 8;

    /// Variable-time basepoint table for NIST P-384's generator.
    type BasepointTableVartime =
        elliptic_curve::point::BasepointTableVartime<ProjectivePoint, WINDOW_SIZE_VARTIME>;

    /// Lazily computed basepoint table.
    pub(crate) static BASEPOINT_TABLE_VARTIME: BasepointTableVartime = BasepointTableVartime::new();

    impl PrimeCurveWithBasepointTableVartime<WINDOW_SIZE_VARTIME> for Sm2 {
        const BASEPOINT_TABLE_VARTIME: &'static BasepointTableVartime = &BASEPOINT_TABLE_VARTIME;
    }
}
