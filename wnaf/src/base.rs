use crate::{WindowSize, WnafScalar, WnafSize, wnaf_multi_exp, wnaf_table};
use array::Array;
use core::iter;
use core::ops::Mul;
use group::Group;

/// Fixed window table for a group element, precomputed to improve scalar multiplication speed.
///
/// By fixing the window size at compile time, we are able to support fully `no_alloc`
/// stack-allocated operation, and also use the type system to ensure [`WnafBase`] and
/// [`WnafScalar`] are using the same window size.
///
/// Precomputations are guaranteed to only occur once per base and once per scalar. Users should
/// select their window size based on how long the bases are expected to live; a larger window size
/// will consume more memory and take longer to precompute, but result in faster scalar
/// multiplications.
///
/// # Examples
///
/// ```ignore
/// type MyWnafBase = WnafBase<ProjectivePoint, U5, U8>;
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
    pub fn new(base: &G) -> Self {
        let mut ret = Self::default();
        ret.init_from_base(base);
        ret
    }

    /// Initialize an already allocated window table from the given base.
    #[inline]
    pub fn init_from_base(&mut self, base: &G) {
        wnaf_table(&mut self.table, base, W::USIZE);
    }

    /// Perform a multiscalar multiplication.
    ///
    /// Computes a sum-of-products `aA + bB + ...` in variable time with w-NAF multi-exponentiation
    /// using the interleaved window method, also known as Straus's method.
    #[must_use]
    pub fn multiscalar_mul<'a, I>(pairs: I) -> G
    where
        G::Scalar: WnafSize,
        I: Clone + Iterator<Item = (&'a Self, &'a WnafScalar<G::Scalar, W>)>,
    {
        wnaf_multi_exp(pairs.map(|(b, s)| (b.table.as_slice(), s.wnaf.as_slice(), s.digits)))
    }
}

impl<G: Group, W: WindowSize> Default for WnafBase<G, W> {
    fn default() -> Self {
        Self {
            table: Array::from_fn(|_| G::generator()),
        }
    }
}

impl<G, W> Mul<&WnafScalar<G::Scalar, W>> for &WnafBase<G, W>
where
    G: Group<Scalar: WnafSize>,
    W: WindowSize,
{
    type Output = G;

    fn mul(self, rhs: &WnafScalar<G::Scalar, W>) -> Self::Output {
        WnafBase::multiscalar_mul(iter::once((self, rhs)))
    }
}

impl<G, W> Mul<&WnafScalar<G::Scalar, W>> for WnafBase<G, W>
where
    G: Group<Scalar: WnafSize>,
    W: WindowSize,
{
    type Output = G;

    #[inline]
    fn mul(self, rhs: &WnafScalar<G::Scalar, W>) -> Self::Output {
        &self * rhs
    }
}

impl<G, W> Mul<WnafScalar<G::Scalar, W>> for WnafBase<G, W>
where
    G: Group<Scalar: WnafSize>,
    W: WindowSize,
{
    type Output = G;

    #[inline]
    fn mul(self, rhs: WnafScalar<G::Scalar, W>) -> Self::Output {
        &self * &rhs
    }
}
