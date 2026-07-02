//! Dynamic wNAF API (requires `alloc` feature).

use crate::{Digit, WnafGroup, le_repr, wnaf_form, wnaf_multi_exp, wnaf_table};
use alloc::vec::Vec;
use ff::PrimeField;
use group::Group;

#[cfg(doc)]
use crate::{WnafBase, WnafScalar};

/// A "w-ary non-adjacent form" scalar multiplication (also known as exponentiation) context.
///
/// # Examples
///
/// This struct can be used to implement several patterns:
///
/// ## One base, one scalar
///
/// For this pattern, you can use a transient [`BoxedWnaf`] context:
///
/// ```ignore
/// use wnaf::BoxedWnaf;
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
/// use wnaf::BoxedWnaf;
///
/// let mut wnaf = BoxedWnaf::new();
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
/// use wnaf::BoxedWnaf;
///
/// let mut wnaf = BoxedWnaf::new();
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
/// pattern, you need to cache the wNAF tables for the bases and then compute the w-NAF
/// form of the scalars on the fly for every base, or vice versa:
///
/// ```ignore
/// use wnaf::BoxedWnaf;
///
/// let mut wnaf_contexts: Vec<_> = (0..bases.len()).map(|_| BoxedWnaf::new()).collect();
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
/// tables and wNAF forms to be cached individually per base and scalar. These types can
/// then be directly multiplied without any additional runtime work, at the cost of fixing
/// a specific window size (rather than choosing the window size dynamically).
#[derive(Debug)]
pub struct BoxedWnaf<W, B, S> {
    base: B,
    scalar: S,
    window_size: W,
}

impl<G: Group> Default for BoxedWnaf<(), Vec<G>, Vec<Digit>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: Group> BoxedWnaf<(), Vec<G>, Vec<Digit>> {
    /// Create a new [`BoxedWnaf`].
    #[must_use]
    pub fn new() -> Self {
        BoxedWnaf {
            base: vec![],
            scalar: vec![],
            window_size: (),
        }
    }
}

impl<G: WnafGroup> BoxedWnaf<(), Vec<G>, Vec<Digit>> {
    /// Construct wNAF base for the provided group element `G`.
    pub fn base(
        &mut self,
        base: &G,
        num_scalars: usize,
    ) -> BoxedWnaf<usize, &[G], &mut Vec<Digit>> {
        let window_size = G::recommended_wnaf_for_num_scalars(num_scalars);

        self.base.resize_with(1 << (window_size - 2), G::identity);
        wnaf_table(&mut self.base, base, window_size);

        BoxedWnaf {
            base: &self.base[..],
            scalar: &mut self.scalar,
            window_size,
        }
    }

    /// Construct wNAF context for `scalar`.
    pub fn scalar(&mut self, scalar: &G::Scalar) -> BoxedWnaf<usize, &mut Vec<G>, &[Digit]> {
        let window_size = 4;

        let repr = le_repr(scalar);
        let bit_len = init_storage::<G::Scalar>(&mut self.scalar, repr);
        let digits = wnaf_form(&mut self.scalar, repr, bit_len, window_size);
        self.scalar.truncate(digits);

        BoxedWnaf {
            base: &mut self.base,
            scalar: &self.scalar[..],
            window_size,
        }
    }
}

impl<'a, G: Group> BoxedWnaf<usize, &'a [G], &'a mut Vec<Digit>> {
    /// Constructs new space for the scalar representation while borrowing the computed window
    /// table, for sending the window table across threads.
    #[must_use]
    pub fn shared(&self) -> BoxedWnaf<usize, &'a [G], Vec<Digit>> {
        BoxedWnaf {
            base: self.base,
            scalar: vec![],
            window_size: self.window_size,
        }
    }
}

impl<'a, G: Group> BoxedWnaf<usize, &'a mut Vec<G>, &'a [Digit]> {
    /// Constructs new space for the window table while borrowing the computed scalar
    /// representation, for sending the scalar representation across threads.
    #[must_use]
    pub fn shared(&self) -> BoxedWnaf<usize, Vec<G>, &'a [Digit]> {
        BoxedWnaf {
            base: vec![],
            scalar: self.scalar,
            window_size: self.window_size,
        }
    }
}

impl<B, S: AsRef<[Digit]>> BoxedWnaf<usize, B, S> {
    /// Construct wNAF base for the provided group element `G`.
    pub fn base<G: Group>(&mut self, base: &G) -> G
    where
        B: AsMut<Vec<G>>,
    {
        self.base
            .as_mut()
            .resize_with(1 << (self.window_size - 2), G::identity);
        wnaf_table(self.base.as_mut(), base, self.window_size);
        wnaf_exp(self.base.as_mut(), self.scalar.as_ref())
    }
}

impl<B, S: AsMut<Vec<Digit>>> BoxedWnaf<usize, B, S> {
    /// Construct wNAF context for `scalar`.
    pub fn scalar<G: Group>(&mut self, scalar: &G::Scalar) -> G
    where
        B: AsRef<[G]>,
    {
        let repr = le_repr(scalar);
        let bit_len = init_storage::<G::Scalar>(self.scalar.as_mut(), repr);
        let digits = wnaf_form(self.scalar.as_mut(), repr, bit_len, self.window_size);
        self.scalar.as_mut().truncate(digits);
        wnaf_exp(self.base.as_ref(), self.scalar.as_mut())
    }
}

/// Initialize storage for wNAF `Digit`s.
#[inline]
fn init_storage<F: PrimeField>(digits: &mut Vec<Digit>, repr: F::Repr) -> usize {
    let bit_len = (repr.as_ref().len() * 8).min(F::NUM_BITS as usize);
    digits.resize(bit_len + 1, 0);
    bit_len
}

/// Performs wNAF exponentiation with the provided window table and w-NAF form scalar, whose
/// lengths must match.
#[inline]
fn wnaf_exp<G: Group>(table: &[G], wnaf: &[Digit]) -> G {
    wnaf_multi_exp(core::iter::once((table, wnaf, wnaf.len())))
}
