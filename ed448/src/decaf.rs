// This will be the module for Decaf over Ed448
// This is the newer version of the Decaf strategy, which looks simpler

pub mod affine;
mod ops;
pub mod points;

pub use affine::AffinePoint;
pub use points::{CompressedDecaf, DecafPoint};
