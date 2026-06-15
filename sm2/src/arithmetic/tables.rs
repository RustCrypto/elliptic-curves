//! Precomputed tables (optional).

use super::Sm2;
use crate::ProjectivePoint;
use primeorder::PrimeCurveWithBasepointTable;

/// Window size for the basepoint table.
const WINDOW_SIZE: usize = 33;

/// Basepoint table for multiples of NIST P-256's generator.
type BasepointTable = primeorder::BasepointTable<ProjectivePoint, WINDOW_SIZE>;

/// Lazily computed basepoint table.
pub(super) static BASEPOINT_TABLE: BasepointTable = BasepointTable::new();

impl PrimeCurveWithBasepointTable<WINDOW_SIZE> for Sm2 {
    const BASEPOINT_TABLE: &'static BasepointTable = &BASEPOINT_TABLE;
}
