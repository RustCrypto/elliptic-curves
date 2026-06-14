//! Precomputed tables (optional).

use super::NistP256;
use crate::ProjectivePoint;
use primeorder::PrimeCurveWithBasepointTable;

#[cfg(feature = "alloc")]
pub(super) use vartime::BASEPOINT_TABLE_VARTIME;

/// Window size for the basepoint table.
const WINDOW_SIZE: usize = 33;

/// Basepoint table for multiples of secp256r1's generator.
type BasepointTable = primeorder::BasepointTable<ProjectivePoint, WINDOW_SIZE>;

/// Lazily computed basepoint table.
pub(super) static BASEPOINT_TABLE: BasepointTable = BasepointTable::new();

impl PrimeCurveWithBasepointTable<WINDOW_SIZE> for NistP256 {
    const BASEPOINT_TABLE: &'static BasepointTable = &BASEPOINT_TABLE;
}

#[cfg(feature = "alloc")]
mod vartime {
    use crate::{NistP256, ProjectivePoint};
    use primeorder::PrimeCurveWithBasepointTableVartime;

    /// Window size for the variable-time basepoint table.
    const WINDOW_SIZE_VARTIME: usize = 8;

    /// Variable-time basepoint table for NIST P-256's generator.
    type BasepointTableVartime =
        primeorder::BasepointTableVartime<ProjectivePoint, WINDOW_SIZE_VARTIME>;

    /// Lazily computed basepoint table.
    pub(crate) static BASEPOINT_TABLE_VARTIME: BasepointTableVartime = BasepointTableVartime::new();

    impl PrimeCurveWithBasepointTableVartime<WINDOW_SIZE_VARTIME> for NistP256 {
        const BASEPOINT_TABLE_VARTIME: &'static BasepointTableVartime = &BASEPOINT_TABLE_VARTIME;
    }
}

/// These are the main tests for `primeorder::BasepointTable` as we need a concrete curve to test
/// against.
#[cfg(test)]
mod tests {
    use super::BASEPOINT_TABLE;
    use crate::{ProjectivePoint, Scalar};
    use elliptic_curve::{
        array::{Array, sizes::U32},
        ops::Reduce,
    };
    use proptest::prelude::*;

    prop_compose! {
        fn scalar()(bytes in any::<[u8; 32]>()) -> Scalar {
            Scalar::reduce(&Array::<u8, U32>::from(bytes))
        }
    }

    proptest! {
        #[test]
        fn basepoint_table_mul(x in scalar()) {
            let expected = ProjectivePoint::GENERATOR * &x;
            let actual = BASEPOINT_TABLE.mul(&x);
            prop_assert_eq!(expected, actual);
        }
    }
}
