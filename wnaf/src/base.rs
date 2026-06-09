use crate::{WnafScalar, wnaf_exp, wnaf_multi_exp, wnaf_table};
use alloc::vec::Vec;
use core::ops::Mul;
use group::Group;

/// A fixed window table for a group element, precomputed to improve the speed of scalar
/// multiplication.
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
/// use group::{WnafBase, WnafScalar};
///
/// let wnaf_bases: Vec<_> = bases.into_iter().map(WnafBase::<_, 4>::new).collect();
/// let wnaf_scalars: Vec<_> = scalars.iter().map(WnafScalar::new).collect();
/// let results: Vec<_> = wnaf_bases
///     .iter()
///     .flat_map(|base| wnaf_scalars.iter().map(|scalar| base * scalar))
///     .collect();
/// ```
///
/// Note that this pattern requires specifying a fixed window size (unlike previous
/// patterns that picked a suitable window size internally). This is necessary to ensure
/// in the type system that the base and scalar `Wnaf`s were computed with the same window
/// size, allowing the result to be computed infallibly.
#[derive(Clone, Debug)]
pub struct WnafBase<G: Group, const WINDOW_SIZE: usize> {
    table: Vec<G>,
}

impl<G: Group, const WINDOW_SIZE: usize> WnafBase<G, WINDOW_SIZE> {
    /// Computes a window table for the given base with the specified `WINDOW_SIZE`.
    pub fn new(base: G) -> Self {
        let mut table = vec![];

        // Compute a window table for the provided base and window size.
        wnaf_table(&mut table, base, WINDOW_SIZE);

        WnafBase { table }
    }

    /// Perform a multiscalar multiplication.
    ///
    /// Computes a sum-of-products `aA + bB + ...` in variable time with w-NAF multi-exponentiation
    /// using the interleaved window method, also known as Straus' method.
    pub fn multiscalar_mul<I, J>(scalars: I, bases: J) -> G
    where
        I: IntoIterator<Item = WnafScalar<G::Scalar, WINDOW_SIZE>>,
        J: IntoIterator<Item = Self>,
    {
        let wnafs = scalars.into_iter().map(|s| s.wnaf).collect::<Vec<_>>();
        let tables = bases.into_iter().map(|b| b.table).collect::<Vec<_>>();
        wnaf_multi_exp(tables.as_slice(), wnafs.as_slice())
    }

    /// Perform a multiscalar multiplication over a fixed-size set of scalars and bases.
    ///
    /// Computes a sum-of-products `aA + bB + ...` in variable time with w-NAF multi-exponentiation
    /// using the interleaved window method, also known as Straus' method.
    ///
    /// This is a borrowing, fixed-arity counterpart to [`multiscalar_mul`]: it operates on
    /// `&[_; N]` arrays and borrows the precomputed w-NAF forms and window tables in place,
    /// avoiding the intermediate heap allocations that the iterator-based version performs. It
    /// suits hot paths with a statically known number of terms (for example the four sub-scalars
    /// of a GLV-decomposed `aG + bP`).
    ///
    /// [`multiscalar_mul`]: Self::multiscalar_mul
    #[must_use]
    pub fn multiscalar_mul_array<const N: usize>(
        scalars: &[WnafScalar<G::Scalar, WINDOW_SIZE>; N],
        bases: &[Self; N],
    ) -> G {
        let wnafs = scalars.each_ref().map(|s| s.wnaf.as_slice());
        let tables = bases.each_ref().map(|b| b.table.as_slice());
        wnaf_multi_exp(&tables, &wnafs)
    }
}

impl<G: Group, const WINDOW_SIZE: usize> Mul<&WnafScalar<G::Scalar, WINDOW_SIZE>>
    for &WnafBase<G, WINDOW_SIZE>
{
    type Output = G;

    fn mul(self, rhs: &WnafScalar<G::Scalar, WINDOW_SIZE>) -> Self::Output {
        wnaf_exp(&self.table, &rhs.wnaf)
    }
}
