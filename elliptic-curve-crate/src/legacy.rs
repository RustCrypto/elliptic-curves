//! Traits for implementing legacy protocols.
//!
//! These APIs could be potentially misused when designing new protocols.
//! For that reason, we strongly suggest they aren't used in new protocols, but
//! only as needed when implementing legacy protocols which require them.

/// Reduce the field element representing the x-coordinate of an affine point
/// into the associated scalar type
pub trait ReduceAffineX {
    /// Scalar type
    type Scalar; // TODO: bounds (should we add a `ScalarArith` marker trait?)

    /// Convert the element in the base field representing the x-coordinate
    /// to the associated scalar type by lifting it into an integer and then
    /// reducing it to an element of the scalar field
    fn reduce_x_to_scalar(&self) -> Self::Scalar;
}

/// Determines if the y-coordinate of an affine point is odd
pub trait IsAffineYOdd {
    /// Is the y-coordinate odd?
    fn is_y_odd(&self) -> bool;
}
