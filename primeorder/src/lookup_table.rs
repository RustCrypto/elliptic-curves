use elliptic_curve::{
    Group,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
};

#[cfg(all(
    feature = "basepoint-table",
    not(any(feature = "critical-section", feature = "std"))
))]
compile_error!("`basepoint-table` feature requires either `critical-section` or `std`");

#[cfg(feature = "basepoint-table")]
use core::ops::Deref;

#[cfg(all(feature = "basepoint-table", feature = "critical-section"))]
use once_cell::sync::Lazy as LazyLock;
#[cfg(all(
    feature = "basepoint-table",
    all(feature = "std", not(feature = "critical-section"))
))]
use std::sync::LazyLock;

/// Internal constant for the number of entries in a [`LookupTable`].
const LUT_SIZE: usize = 8;

/// Lookup table containing precomputed values `[p, 2p, 3p, ..., 8p]`
#[derive(Clone, Copy, Debug, Default)]
pub struct LookupTable<Point> {
    points: [Point; LUT_SIZE],
}

impl<Point> LookupTable<Point>
where
    Point: ConditionallySelectable + Group,
{
    /// Compute a new lookup table from the given point.
    pub fn new(p: Point) -> Self {
        let mut points = [p; 8];

        for j in 0..(LUT_SIZE - 1) {
            points[j + 1] = p + &points[j];
        }

        Self { points }
    }

    /// Given -8 <= x <= 8, returns x * p in constant time.
    pub fn select(&self, x: i8) -> Point {
        debug_assert!((-8..=8).contains(&x));

        // Compute xabs = |x|
        let xmask = x >> 7;
        let xabs = (x + xmask) ^ xmask;

        // Get an array element in constant time
        let mut t = Point::identity();

        for j in 1..(8 + 1) {
            let c = (xabs as u8).ct_eq(&(j as u8));
            t.conditional_assign(&self.points[j - 1], c);
        }
        // Now t == |x| * p.

        let neg_mask = Choice::from((xmask & 1) as u8);
        t.conditional_assign(&-t, neg_mask);
        // Now t == x * p.

        t
    }
}

/// Precomputed lookup table of multiples of a base point, a.k.a. generator.
#[cfg(feature = "basepoint-table")]
pub struct BasepointTable<Point, const N: usize> {
    tables: LazyLock<[LookupTable<Point>; N]>,
}

#[cfg(feature = "basepoint-table")]
impl<Point, const N: usize> BasepointTable<Point, N>
where
    Point: ConditionallySelectable + Default + Group,
{
    /// Create a new [`BasepointTable`] which is lazily initialized on first use and can be bound
    /// to a constant.
    ///
    /// Computed using [`Point::generator()`] as the base point.
    pub const fn new() -> Self {
        /// Inner function to initialize the table.
        fn init_table<Point, const N: usize>() -> [LookupTable<Point>; N]
        where
            Point: ConditionallySelectable + Default + Group,
        {
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

#[cfg(feature = "basepoint-table")]
impl<Point, const N: usize> Deref for BasepointTable<Point, N> {
    type Target = [LookupTable<Point>; N];

    #[inline]
    fn deref(&self) -> &[LookupTable<Point>; N] {
        &self.tables
    }
}
