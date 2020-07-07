//! Support for implementing legacy protocols that require direct access to
//! coordinates of affine points on elliptic curves.
//!
//! These APIs violate the group abstraction and expose coordinate field
//! elements which could be potentially misused when designing new protocols
//! based on elliptic curve groups.
//!
//! For that reason, we strongly suggest they aren't used in new protocols, but
//! only as needed when implementing legacy protocols which require them.

use generic_array::ArrayLength;

/// Byte array containing a serialized field element
pub type FieldElementBytes<Size> = generic_array::GenericArray<u8, Size>;

/// Access to the coordinates of an affine point
pub trait AffineCoordinates {
    /// Size of a field element representing an affine coordinate
    type FieldElementSize: ArrayLength<u8>;

    /// x-coordinate (field element)
    fn x(&self) -> FieldElementBytes<Self::FieldElementSize>;

    /// y-coordinate (field element)
    fn y(&self) -> FieldElementBytes<Self::FieldElementSize>;
}
