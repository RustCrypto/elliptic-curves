//! Precomputed tables (optional).
//!
//! We only provide a constant-time basepoint table here as the generic wNAF implementation in the
//! `group` crate doesn't support the secp256k1 endomorphism optimization and thus winds up being
//! slower than the constant-time version (see RustCrypto/elliptic-curves

use crate::ProjectivePoint;
use elliptic_curve::point::PointWithBasepointTable;

/// Window size for the basepoint table.
const WINDOW_SIZE: usize = 33;

/// Basepoint table for multiples of secp256k1's generator.
type BasepointTable = elliptic_curve::point::BasepointTable<ProjectivePoint, WINDOW_SIZE>;

/// Lazily computed basepoint table.
pub(super) static BASEPOINT_TABLE: BasepointTable = BasepointTable::new();

impl PointWithBasepointTable<WINDOW_SIZE> for ProjectivePoint {
    const BASEPOINT_TABLE: &'static BasepointTable = &BASEPOINT_TABLE;
}
