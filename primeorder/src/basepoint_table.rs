//! Precomputed basepoint tables for accelerating fixed-base scalar multiplication.

#![allow(clippy::cast_possible_truncation, clippy::needless_range_loop)]

#[cfg(not(any(feature = "critical-section", feature = "std")))]
compile_error!("`basepoint-table` feature requires either `critical-section` or `std`");

use super::{LookupTable, Radix16Decomposition, Radix16Digits};
use crate::{PrimeCurveParams, ProjectivePoint, Scalar};
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
        let digits = Radix16Decomposition::<Radix16Digits<C>>::new(k, true);
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

#[cfg(feature = "alloc")]
pub(crate) mod vartime {
    use super::LazyLock;
    use alloc::vec::Vec;
    use core::ops::Mul;
    use elliptic_curve::group::Group;
    use wnaf::{WnafBase, WnafScalar};

    /// Window table for a curve's base point (a.k.a. generator) precomputed to improve the speed of
    /// variable-time scalar multiplication.
    ///
    /// <div class = "warning">
    /// <b>Security Warning</b>
    ///
    /// Variable-time scalar multiplication can potentially leak secret values and should NOT be
    /// used with them.
    /// </div>
    ///
    /// This type leverages lazy computation, and requires one of the following crate features to be
    /// enabled in order to work:
    /// - `std`: leverages `std::sync::LazyLock`
    /// - `critical-section`: leverages `once_cell::sync::Lazy` via the `critical-section` crate,
    ///   enabling the feature to be used in `no_std` contexts.
    #[derive(Debug)]
    pub struct BasepointTableVartime<Point: Group, const WINDOW_SIZE: usize> {
        table: LazyLock<WnafBase<Point, WINDOW_SIZE>>,
    }

    impl<Point: Group, const WINDOW_SIZE: usize> BasepointTableVartime<Point, WINDOW_SIZE> {
        /// Create a new [`BasepointTableVartime`] which is lazily initialized on first use and can
        /// be bound to a constant.
        ///
        /// Computed using the `Point`'s [`Group::generator`] as the base point.
        pub const fn new() -> Self {
            /// Inner function to initialize the wNAF context.
            fn init_wnaf<Point, const N: usize>() -> WnafBase<Point, N>
            where
                Point: Group,
            {
                WnafBase::new(Point::generator())
            }

            Self {
                table: LazyLock::new(init_wnaf),
            }
        }

        /// Multiply `Point::generator` by the given scalar in variable-time, using the precomputed
        /// window table to accelerate the scalar multiplication.
        pub fn mul(&self, scalar: &Point::Scalar) -> Point {
            self.table.mul(&WnafScalar::new(scalar))
        }

        /// Multiply `Point::generator` by the given scalar in variable-time, then compute a linear
        /// combination of the remaining points and scalars, i.e.
        ///
        /// ```text
        /// scalar * G + scalars[0] * Points[0] + ...
        /// ```
        pub fn lincomb(
            &self,
            scalar: &Point::Scalar,
            points_and_scalars: &[(Point, Point::Scalar)],
        ) -> Point {
            let mut bases = Vec::with_capacity(points_and_scalars.len() + 1);
            bases.push(self.table.clone());
            bases.extend(
                points_and_scalars
                    .iter()
                    .map(|(point, _)| WnafBase::new(*point)),
            );

            let mut scalars = Vec::with_capacity(points_and_scalars.len() + 1);
            scalars.push(WnafScalar::new(scalar));
            scalars.extend(
                points_and_scalars
                    .iter()
                    .map(|(_, scalar)| WnafScalar::new(scalar)),
            );

            WnafBase::multiscalar_mul(scalars, bases)
        }
    }

    impl<Point: Group, const WINDOW_SIZE: usize> Default for BasepointTableVartime<Point, WINDOW_SIZE> {
        fn default() -> Self {
            Self::new()
        }
    }
}
