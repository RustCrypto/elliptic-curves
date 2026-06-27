//! Trait definitions.

use array::{
    ArraySize,
    typenum::{U1, U2, U3, U4, U5, U6, U7, U8, U16, U32, U64, Unsigned},
};
use ff::PrimeField;
use group::Group;

/// Extension trait on a [`Group`] that provides helpers used by [`crate::BoxedWnaf`].
pub trait WnafGroup: Group {
    /// Recommends a wNAF window size given the number of scalars you intend to multiply
    /// a base by. Always returns a number between 2 and [`W_MAX`][`crate::W_MAX`], inclusive.
    fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize;
}

/// Size of the w-NAF representation: this should be the type-level equivalent of
/// `PrimeField::NUM_BITS + 1`, which includes an extra entry for any remaining carry.
pub trait WnafSize: PrimeField {
    /// Number of digits in the w-NAF representation.
    type StorageSize: ArraySize;
}

/// Allowed w-NAF window size: we use this to precompute the window point sizes, because it's
/// currently not possible to write bounds for them.
pub trait WindowSize: Unsigned {
    /// Number of precomputed points in the window table: `1 << (Self::USIZE - 2)`.
    type TableSize: ArraySize;
}

// TODO(tarcieri): compute or failing that test window sizes
macro_rules! impl_window_sizes {
    ($($window_size:ty => $table_size:ty),+) => {
        $(
            impl WindowSize for $window_size {
                type TableSize = $table_size;
            }
        )+
    };
}

// NOTE: the maximum size supported here should match the `W_MAX` constant
impl_window_sizes!(U2 => U1, U3 => U2, U4 => U4, U5 => U8, U6 => U16, U7 => U32, U8 => U64);
