//! Elliptic curves in short Weierstrass form.

pub mod curve;
pub mod point;
pub mod public_key;

pub use curve::Curve;
pub use point::{
    CompressedCurvePoint, CompressedPointSize, UncompressedCurvePoint, UncompressedPointSize,
};
pub use public_key::PublicKey;

use crate::{consts::U1, coordinates::AffineCoordinates, ScalarBytes};
use core::ops::Add;
use generic_array::ArrayLength;
use subtle::{ConditionallySelectable, CtOption};

/// Fixed-base scalar multiplication
pub trait FixedBaseScalarMul: Curve
where
    <Self::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<Self::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<Self::ScalarSize>: ArrayLength<u8>,
{
    /// Affine point type for this elliptic curve
    type Point: AffineCoordinates + ConditionallySelectable + Default;

    /// Multiply the given scalar by the generator point for this elliptic
    /// curve.
    fn mul_base(scalar: &ScalarBytes<Self::ScalarSize>) -> CtOption<Self::Point>;
}
