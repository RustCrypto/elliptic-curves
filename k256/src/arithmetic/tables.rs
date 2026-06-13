//! Precomputed tables (optional).
//!
//! We only provide a constant-time basepoint table here as the generic wNAF implementation in the
//! `group` crate doesn't support the secp256k1 endomorphism optimization and thus winds up being
//! slower than the constant-time version (see RustCrypto/elliptic-curves

use super::Secp256k1;
use crate::ProjectivePoint;
use primeorder::PrimeCurveWithBasepointTable;

/// Window size for the basepoint table.
const WINDOW_SIZE: usize = 33;

/// Basepoint table for multiples of secp256k1's generator.
type BasepointTable = primeorder::BasepointTable<ProjectivePoint, WINDOW_SIZE>;

/// Lazily computed basepoint table.
pub(super) static BASEPOINT_TABLE: BasepointTable = BasepointTable::new();

impl PrimeCurveWithBasepointTable<WINDOW_SIZE> for Secp256k1 {
    const BASEPOINT_TABLE: &'static BasepointTable = &BASEPOINT_TABLE;
}
