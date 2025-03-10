/// This module contains the code for the Goldilocks curve.
/// The goldilocks curve is the (untwisted) Edwards curve with affine equation x^2 + y^2 = 1 - 39081x^2y^2
/// Scalar Multiplication for this curve is pre-dominantly delegated to the Twisted Edwards variation using a (doubling) isogeny
/// Passing the point back to the Goldilocks curve using the dual-isogeny clears the cofactor.
/// The small remainder of the Scalar Multiplication is computed on the untwisted curve.
/// See <https://www.shiftleft.org/papers/isogeny/isogeny.pdf> for details
///
/// This isogeny strategy does not clear the cofactor on the Goldilocks curve unless the Scalar is a multiple of 4.
/// or the point is known to be in the q-torsion subgroup.
/// Hence, one will need to multiply by the cofactor to ensure it is cleared when using the Goldilocks curve.
/// If this is a problem, one can use a different isogeny strategy (Decaf/Ristretto)
pub(crate) mod affine;
pub(crate) mod extended;
pub use affine::AffinePoint;
pub use extended::{CompressedEdwardsY, EdwardsPoint};
