use crate::{WindowSize, WnafScalar, wnaf_multi_exp, wnaf_table};
use array::{Array, ArraySize};
use core::iter;
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
    #[inline]
    pub fn new(base: G) -> Self {
        let mut ret = Self {
            table: Array::from_fn(|_| G::generator()),
        };
        wnaf_table(&mut ret.table, base, W::USIZE);
        ret
    }

    /// Perform a multiscalar multiplication.
    ///
    /// Computes a sum-of-products `aA + bB + ...` in variable time with w-NAF multi-exponentiation
    /// using the interleaved window method, also known as Straus's method.
    #[must_use]
    pub fn multiscalar_mul<'a, WnafStorage, I>(pairs: I) -> G
    where
        WnafStorage: ArraySize,
        I: Clone + Iterator<Item = (&'a Self, &'a WnafScalar<G::Scalar, W, WnafStorage>)>,
    {
        wnaf_multi_exp(pairs.map(|(b, s)| (b.table.as_slice(), s.wnaf.as_slice(), s.digits)))
    }
}

impl<G: Group, W: WindowSize, WnafStorage: ArraySize> Mul<&WnafScalar<G::Scalar, W, WnafStorage>>
    for &WnafBase<G, W>
{
    type Output = G;

    fn mul(self, rhs: &WnafScalar<G::Scalar, W, WnafStorage>) -> Self::Output {
        WnafBase::multiscalar_mul(iter::once((self, rhs)))
    }
}
