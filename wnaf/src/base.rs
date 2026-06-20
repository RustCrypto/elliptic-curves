use crate::{WindowSize, WnafScalar, wnaf_exp, wnaf_multi_exp, wnaf_table};
use array::{Array, ArraySize};
use core::ops::Mul;
use group::Group;

/// Fixed window table for a group element, precomputed to improve scalar multiplication speed.
///
/// This struct is designed for usage patterns that have long-term cached bases and/or
/// scalars, or [Cartesian products] of bases and scalars. The [`Wnaf`] API enables one or
/// the other to be cached, but requires either the base window tables or the scalar w-NAF
/// forms to be computed repeatedly on the fly, which can become a significant performance
/// issue for some use cases.
///
/// `WnafBase` and [`WnafScalar`] enable an alternative trade-off: by fixing the window
/// size at compile time, the precomputations are guaranteed to only occur once per base
/// and once per scalar. Users should select their window size based on how long the bases
/// are expected to live; a larger window size will consume more memory and take longer to
/// precompute, but result in faster scalar multiplications.
///
/// [Cartesian products]: https://en.wikipedia.org/wiki/Cartesian_product
///
/// # Examples
///
/// ```ignore
/// type MyWnafBase   = WnafBase<ProjectivePoint, U5, U8>;
/// type MyWnafScalar = WnafScalar<Scalar, U5, U129>;
///
/// let base = MyWnafBase::new(ProjectivePoint::GENERATOR);
/// let scalar = MyWnafScalar::new(&s);
/// let result = base * scalar;
/// ```
///
/// Note that this pattern requires specifying a fixed window size `W`. This is necessary to ensure
/// in the type system that the base and scalar `Wnaf`s were computed with the same window
/// size, allowing the result to be computed infallibly.
#[derive(Clone, Debug)]
pub struct WnafBase<G: Group, W: WindowSize> {
    table: Array<G, W::TableSize>,
}

impl<G: Group, W: WindowSize> WnafBase<G, W> {
    /// Computes a window table for the given base with the specified window size `W`.
    pub fn new(base: G) -> Self {
        WnafBase {
            table: wnaf_table(base, W::USIZE),
        }
    }

    /// Perform a multiscalar multiplication.
    ///
    /// Computes a sum-of-products `aA + bB + ...` in variable time with w-NAF multi-exponentiation
    /// using the interleaved window method, also known as Straus's method.
    ///
    /// `scalars` and `bases` must have the same length.
    #[must_use]
    pub fn multiscalar_mul<WnafStorage: ArraySize>(
        scalars: &[WnafScalar<G::Scalar, W, WnafStorage>],
        bases: &[Self],
    ) -> G {
        let terms = bases
            .iter()
            .zip(scalars.iter())
            .map(|(b, s)| (b.table.as_slice(), s.wnaf.as_slice(), s.digits));

        wnaf_multi_exp(terms)
    }
}

impl<G: Group, W: WindowSize, WnafStorage: ArraySize> Mul<&WnafScalar<G::Scalar, W, WnafStorage>>
    for &WnafBase<G, W>
{
    type Output = G;

    fn mul(self, rhs: &WnafScalar<G::Scalar, W, WnafStorage>) -> Self::Output {
        wnaf_exp(&self.table, &rhs.wnaf, rhs.digits)
    }
}
