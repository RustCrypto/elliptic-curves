//! Precomputed tables (optional).

use super::NistP256;
use crate::ProjectivePoint;
use primeorder::PrimeCurveWithBasepointTable;

/// Window size for the basepoint table (1 + 32-byte modulus)
pub(super) const WINDOW_SIZE: usize = 33;

/// Basepoint table for multiples of NIST P-256's generator.
pub(super) type BasepointTable = primeorder::BasepointTable<ProjectivePoint, WINDOW_SIZE>;

/// Lazily computed basepoint table.
pub(super) static BASEPOINT_TABLE: BasepointTable = BasepointTable::new();

impl PrimeCurveWithBasepointTable<WINDOW_SIZE> for NistP256 {
    const BASEPOINT_TABLE: &'static BasepointTable = &BASEPOINT_TABLE;
}

/// Workaround for rust-lang/rust#140653 to support MSRV 1.85: we can't use the generic
/// implementation in `primeorder::backend::PrecomputedTables` until MSRV 1.90 due to restrictions
/// on referencing a type with interior mutability from a `const`.
// TODO(tarcieri): remove this and switch to `primeorder::backend::PrecomputedTables` when MSRV 1.90
pub(crate) mod backend {
    use super::BASEPOINT_TABLE;
    use crate::{NistP256, ProjectivePoint, Scalar};
    use primeorder::Backend;

    /// Backend based on precomputed tables.
    pub struct PrecomputedTables;

    impl Backend<NistP256> for PrecomputedTables {
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
