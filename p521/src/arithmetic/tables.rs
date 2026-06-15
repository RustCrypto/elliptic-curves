//! Precomputed tables (optional).

use super::NistP521;
use crate::ProjectivePoint;
use primeorder::PrimeCurveWithBasepointTable;

/// Window size for the basepoint table.
const WINDOW_SIZE: usize = 67;

/// Basepoint table for multiples of NIST P-521's generator.
type BasepointTable = primeorder::BasepointTable<ProjectivePoint, WINDOW_SIZE>;

/// Lazily computed basepoint table.
pub(super) static BASEPOINT_TABLE: BasepointTable = BasepointTable::new();

impl PrimeCurveWithBasepointTable<WINDOW_SIZE> for NistP521 {
    const BASEPOINT_TABLE: &'static BasepointTable = &BASEPOINT_TABLE;
}
