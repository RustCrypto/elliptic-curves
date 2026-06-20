//! Dynamic w-NAF API (requires `alloc` feature).
// TODO(tarcieri): actually make this work with the API changes to e.g. `wnaf_table`

use crate::{WnafBase, WnafGroup, WnafScalar, le_repr, wnaf_exp, wnaf_form, wnaf_table};
use alloc::vec::Vec;
use group::Group;

/// A "w-ary non-adjacent form" scalar multiplication (also known as exponentiation)
/// context.
///
/// # Examples
///
/// This struct can be used to implement several patterns:
///
/// ## One base, one scalar
///
/// For this pattern, you can use a transient `Wnaf` context:
///
/// ```ignore
/// use group::Wnaf;
///
/// let result = Wnaf::new().scalar(&scalar).base(base);
/// ```
///
/// ## Many bases, one scalar
///
/// For this pattern, you create a `Wnaf` context, load the scalar into it, and then
/// process each base in turn:
///
/// ```ignore
/// use group::Wnaf;
///
/// let mut wnaf = Wnaf::new();
/// let mut wnaf_scalar = wnaf.scalar(&scalar);
/// let results: Vec<_> = bases
///     .into_iter()
///     .map(|base| wnaf_scalar.base(base))
///     .collect();
/// ```
///
/// ## One base, many scalars
///
/// For this pattern, you create a `Wnaf` context, load the base into it, and then process
/// each scalar in turn:
///
/// ```ignore
/// use group::Wnaf;
///
/// let mut wnaf = Wnaf::new();
/// let mut wnaf_base = wnaf.base(base, scalars.len());
/// let results: Vec<_> = scalars
///     .iter()
///     .map(|scalar| wnaf_base.scalar(scalar))
///     .collect();
/// ```
///
/// ## Many bases, many scalars
///
/// Say you have `n` bases and `m` scalars, and want to produce `n * m` results. For this
/// pattern, you need to cache the w-NAF tables for the bases and then compute the w-NAF
/// form of the scalars on the fly for every base, or vice versa:
///
/// ```ignore
/// use group::Wnaf;
///
/// let mut wnaf_contexts: Vec<_> = (0..bases.len()).map(|_| Wnaf::new()).collect();
/// let mut wnaf_bases: Vec<_> = wnaf_contexts
///     .iter_mut()
///     .zip(bases)
///     .map(|(wnaf, base)| wnaf.base(base, scalars.len()))
///     .collect();
/// let results: Vec<_> = wnaf_bases
///     .iter()
///     .flat_map(|wnaf_base| scalars.iter().map(|scalar| wnaf_base.scalar(scalar)))
///     .collect();
/// ```
///
/// Alternatively, use the [`WnafBase`] and [`WnafScalar`] types, which enable the various
/// tables and w-NAF forms to be cached individually per base and scalar. These types can
/// then be directly multiplied without any additional runtime work, at the cost of fixing
/// a specific window size (rather than choosing the window size dynamically).
#[derive(Debug)]
pub struct Wnaf<W, B, S> {
    base: B,
    scalar: S,
    window_size: W,
}

impl<G: Group> Default for Wnaf<(), Vec<G>, Vec<i64>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: Group> Wnaf<(), Vec<G>, Vec<i64>> {
    /// Construct a new wNAF context without allocating.
    #[must_use]
    pub fn new() -> Self {
        Wnaf {
            base: vec![],
            scalar: vec![],
            window_size: (),
        }
    }
}

impl<G: WnafGroup> Wnaf<(), Vec<G>, Vec<i64>> {
    /// Given a base and a number of scalars, compute a window table and return a `Wnaf` object that
    /// can perform exponentiations with `.scalar(..)`.
    pub fn base(&mut self, base: G, num_scalars: usize) -> Wnaf<usize, &[G], &mut Vec<i64>> {
        // Compute the appropriate window size based on the number of scalars.
        let window_size = G::recommended_wnaf_for_num_scalars(num_scalars);

        // Compute a wNAF table for the provided base and window size.
        wnaf_table(&mut self.base, base, window_size);

        // Return a Wnaf object that immutably borrows the computed base storage location,
        // but mutably borrows the scalar storage location.
        Wnaf {
            base: &self.base[..],
            scalar: &mut self.scalar,
            window_size,
        }
    }

    /// Given a scalar, compute its wNAF representation and return a `Wnaf` object that can perform
    /// exponentiations with `.base(..)`.
    pub fn scalar(&mut self, scalar: &<G as Group>::Scalar) -> Wnaf<usize, &mut Vec<G>, &[i64]> {
        // We hard-code a window size of 4.
        let window_size = 4;

        // Compute the wNAF form of the scalar.
        wnaf_form(&mut self.scalar, le_repr(scalar), window_size);

        // Return a Wnaf object that mutably borrows the base storage location, but
        // immutably borrows the computed wNAF form scalar location.
        Wnaf {
            base: &mut self.base,
            scalar: &self.scalar[..],
            window_size,
        }
    }
}

impl<'a, G: Group> Wnaf<usize, &'a [G], &'a mut Vec<i64>> {
    /// Constructs new space for the scalar representation while borrowing
    /// the computed window table, for sending the window table across threads.
    #[must_use]
    pub fn shared(&self) -> Wnaf<usize, &'a [G], Vec<i64>> {
        Wnaf {
            base: self.base,
            scalar: vec![],
            window_size: self.window_size,
        }
    }
}

impl<'a, G: Group> Wnaf<usize, &'a mut Vec<G>, &'a [i64]> {
    /// Constructs new space for the window table while borrowing
    /// the computed scalar representation, for sending the scalar representation
    /// across threads.
    #[must_use]
    pub fn shared(&self) -> Wnaf<usize, Vec<G>, &'a [i64]> {
        Wnaf {
            base: vec![],
            scalar: self.scalar,
            window_size: self.window_size,
        }
    }
}

impl<B, S: AsRef<[i64]>> Wnaf<usize, B, S> {
    /// Performs exponentiation given a base.
    pub fn base<G: Group>(&mut self, base: G) -> G
    where
        B: AsMut<Vec<G>>,
    {
        wnaf_table(self.base.as_mut(), base, self.window_size);
        wnaf_exp(self.base.as_mut(), self.scalar.as_ref())
    }
}

impl<B, S: AsMut<Vec<i64>>> Wnaf<usize, B, S> {
    /// Performs exponentiation given a scalar.
    pub fn scalar<G: Group>(&mut self, scalar: &<G as Group>::Scalar) -> G
    where
        B: AsRef<[G]>,
    {
        wnaf_form(self.scalar.as_mut(), le_repr(scalar), self.window_size);
        wnaf_exp(self.base.as_ref(), self.scalar.as_mut())
    }
}
