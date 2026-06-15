//! Precomputed tables (optional).

use super::NistP384;
use crate::ProjectivePoint;
use primeorder::PrimeCurveWithBasepointTable;

/// Window size for the basepoint table (1 + 48-byte modulus)
const WINDOW_SIZE: usize = 49;

/// Basepoint table for multiples of NIST P-384's generator.
type BasepointTable = primeorder::BasepointTable<ProjectivePoint, WINDOW_SIZE>;

/// Lazily computed basepoint table.
pub(super) static BASEPOINT_TABLE: BasepointTable = BasepointTable::new();

impl PrimeCurveWithBasepointTable<WINDOW_SIZE> for NistP384 {
    const BASEPOINT_TABLE: &'static BasepointTable = &BASEPOINT_TABLE;
}
