//! Precomputed basepoint tables for accelerating fixed-base scalar multiplication.

#![allow(clippy::cast_possible_truncation, clippy::needless_range_loop)]

#[cfg(not(any(feature = "critical-section", feature = "std")))]
compile_error!("`basepoint-table` feature requires either `critical-section` or `std`");

use super::LookupTable;
use crate::{PrimeCurveParams, ProjectivePoint, Radix16Decomposition, Radix16Digits, Scalar};
use core::ops::Deref;
use elliptic_curve::{
    FieldBytesSize, array::typenum::Unsigned, ff::PrimeField, group::Group,
    subtle::ConditionallySelectable,
};

#[cfg(feature = "critical-section")]
use once_cell::sync::Lazy as LazyLock;
#[cfg(all(feature = "std", not(feature = "critical-section")))]
use std::sync::LazyLock;

/// Precomputed lookup table of multiples of a base point, a.k.a. generator.
///
/// This type leverages lazy computation, and requires one of the following crate features to be
/// enabled in order to work:
/// - `std`: leverages `std::sync::LazyLock`
/// - `critical-section`: leverages `once_cell::sync::Lazy` via the `critical-section` crate,
///   enabling the feature to be used in `no_std` contexts.
#[derive(Debug)]
pub struct BasepointTable<Point, const WINDOW_SIZE: usize> {
    tables: LazyLock<[LookupTable<Point>; WINDOW_SIZE]>,
}

impl<Point, const WINDOW_SIZE: usize> BasepointTable<Point, WINDOW_SIZE>
where
    Point: ConditionallySelectable + Default + Group,
{
    /// Create a new [`BasepointTable`] which is lazily initialized on first use and can be bound
    /// to a constant.
    ///
    /// Computed using the `Point`'s [`Group::generator`] as the base point.
    pub const fn new() -> Self {
        /// Inner function to initialize the table.
        fn init_table<Point, const N: usize>() -> [LookupTable<Point>; N]
        where
            Point: ConditionallySelectable + Default + Group,
        {
            // Ensure basepoint table contains the expected number of entries for the scalar's size
            const {
                assert!(
                    N as u32 == 1 + Point::Scalar::NUM_BITS.div_ceil(8),
                    "incorrectly sized basepoint table"
                );
            }

            let mut generator = Point::generator();
            let mut res = [LookupTable::<Point>::default(); N];

            for i in 0..N {
                res[i] = LookupTable::new(generator);

                // We are storing tables spaced by two radix steps,
                // to decrease the size of the precomputed data.
                for _ in 0..8 {
                    generator = generator.double();
                }
            }

            res
        }

        Self {
            tables: LazyLock::new(init_table),
        }
    }
}

impl<C: PrimeCurveParams, const WINDOW_SIZE: usize>
    BasepointTable<ProjectivePoint<C>, WINDOW_SIZE>
{
    /// Multiply `Point::generator` by the given scalar in constant-time, using the precomputed
    /// basepoint table to accelerate the scalar multiplication.
    pub fn mul(&self, k: &Scalar<C>) -> ProjectivePoint<C> {
        let digits = Radix16Decomposition::<Radix16Digits<C>>::new(k);
        let len = FieldBytesSize::<C>::USIZE;
        let mut acc = self[len].select(digits[len * 2]);
        let mut acc2 = ProjectivePoint::<C>::IDENTITY;
        for i in (0..len).rev() {
            acc2 += &self[i].select(digits[i * 2 + 1]);
            acc += &self[i].select(digits[i * 2]);
        }

        // This is the price of halving the precomputed table size.
        for _ in 0..4 {
            acc2 = acc2.double();
        }

        acc + acc2
    }

    /// Multiply `Point::generator` by the given scalar in constant-time, using the precomputed
    /// basepoint table to accelerate the scalar multiplication.
    ///
    /// <div class = "warning">
    /// <b>Security Warning</b>
    ///
    /// Variable-time scalar multiplication can potentially leak secret values and should NOT be
    /// used with them.
    /// </div>
    pub fn mul_vartime(&self, k: &Scalar<C>) -> ProjectivePoint<C> {
        let digits = Radix16Decomposition::<Radix16Digits<C>>::new(k);
        let len = FieldBytesSize::<C>::USIZE;
        let mut acc = self[len].select_vartime(digits[len * 2]);
        let mut acc2 = ProjectivePoint::<C>::IDENTITY;
        for i in (0..len).rev() {
            acc2 += &self[i].select_vartime(digits[i * 2 + 1]);
            acc += &self[i].select_vartime(digits[i * 2]);
        }

        // This is the price of halving the precomputed table size.
        for _ in 0..4 {
            acc2 = acc2.double();
        }

        acc + acc2
    }
}

impl<Point, const WINDOW_SIZE: usize> Default for BasepointTable<Point, WINDOW_SIZE>
where
    Point: ConditionallySelectable + Default + Group,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Point, const WINDOW_SIZE: usize> Deref for BasepointTable<Point, WINDOW_SIZE> {
    type Target = [LookupTable<Point>; WINDOW_SIZE];

    #[inline]
    fn deref(&self) -> &[LookupTable<Point>; WINDOW_SIZE] {
        &self.tables
    }
}
