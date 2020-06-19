//! Generic coordinate system support

use crate::ScalarBytes;
use generic_array::ArrayLength;

/// Trait for obtaining the coordinates of an affine point
pub trait AffineCoordinates {
    /// Size of a byte array representing an affine coordinate
    type ScalarSize: ArrayLength<u8>;

    /// x-coordinate
    fn x(&self) -> ScalarBytes<Self::ScalarSize>;

    /// y-coordinate
    fn y(&self) -> ScalarBytes<Self::ScalarSize>;
}
