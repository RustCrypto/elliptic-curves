//! Precomputed tables (optional).

use super::NistP256;
use crate::ProjectivePoint;
use primeorder::PrimeCurveWithBasepointTable;

/// Window size for the basepoint table (1 + 32-byte modulus)
const WINDOW_SIZE: usize = 33;

/// Basepoint table for multiples of NIST P-256's generator.
type BasepointTable = primeorder::BasepointTable<ProjectivePoint, WINDOW_SIZE>;

/// Lazily computed basepoint table.
pub(super) static BASEPOINT_TABLE: BasepointTable = BasepointTable::new();

impl PrimeCurveWithBasepointTable<WINDOW_SIZE> for NistP256 {
    const BASEPOINT_TABLE: &'static BasepointTable = &BASEPOINT_TABLE;
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

    proptest! {
        #[test]
        fn basepoint_table_mul_vartime(x in scalar()) {
            let expected = ProjectivePoint::GENERATOR * &x;
            let actual = BASEPOINT_TABLE.mul_vartime(&x);
            prop_assert_eq!(expected, actual);
        }
    }
}
