#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate alloc;

mod base;
mod limb_buffer;
mod scalar;

pub use crate::{base::WnafBase, scalar::WnafScalar};
pub use group::Group;

use crate::limb_buffer::LimbBuffer;
use alloc::vec::Vec;
use ff::PrimeField;

/// Extension trait on a [`Group`] that provides helpers used by [`Wnaf`].
pub trait WnafGroup: Group {
    /// Recommends a wNAF window size given the number of scalars you intend to multiply
    /// a base by. Always returns a number between 2 and 22, inclusive.
    fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize;
}

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

/// Replaces the contents of `table` with a w-NAF window table for the given window size.
///
/// For a window of size `w`, non-zero wNAF digits are odd and have magnitude at most
/// `2^(w-1) - 1`. The table is indexed by `|digit| / 2`, so the required size is
/// `(2^(w-1) - 1) / 2 + 1 = 2^(w-2)` entries.
fn wnaf_table<G: Group>(table: &mut Vec<G>, mut base: G, window: usize) {
    let table_len = 1 << (window - 2);
    table.clear();
    table.reserve(table_len);

    let dbl = base.double();

    for _ in 0..table_len {
        table.push(base);
        base.add_assign(&dbl);
    }
}

/// Replaces the contents of `wnaf` with the w-NAF representation of a little-endian
/// scalar.
#[allow(clippy::cast_possible_wrap)]
fn wnaf_form<S: AsRef<[u8]>>(wnaf: &mut Vec<i64>, c: S, window: usize) {
    // Required by the NAF definition
    debug_assert!(window >= 2);
    // Required so that the NAF digits fit in i64
    debug_assert!(window <= 64);

    let bit_len = c.as_ref().len() * 8;

    wnaf.clear();
    wnaf.reserve(bit_len);

    // Initialise the current and next limb buffers.
    let mut limbs = LimbBuffer::new(c.as_ref());

    let width = 1u64 << window;
    let window_mask = width - 1;

    let mut pos = 0;
    let mut carry = 0;
    while pos < bit_len {
        // Construct a buffer of bits of the scalar, starting at bit `pos`
        let u64_idx = pos / 64;
        let bit_idx = pos % 64;
        let (cur_u64, next_u64) = limbs.get(u64_idx);
        let bit_buf = if bit_idx + window < 64 {
            // This window's bits are contained in a single u64
            cur_u64 >> bit_idx
        } else {
            // Combine the current u64's bits with the bits from the next u64
            (cur_u64 >> bit_idx) | (next_u64 << (64 - bit_idx))
        };

        // Add the carry into the current window
        let window_val = carry + (bit_buf & window_mask);

        if window_val & 1 == 0 {
            // If the window value is even, preserve the carry and emit 0.
            // Why is the carry preserved?
            // If carry == 0 and window_val & 1 == 0, then the next carry should be 0
            // If carry == 1 and window_val & 1 == 0, then bit_buf & 1 == 1 so the next carry should be 1
            wnaf.push(0);
            pos += 1;
        } else {
            wnaf.push(if window_val < width / 2 {
                carry = 0;
                window_val as i64
            } else {
                carry = 1;
                (window_val as i64).wrapping_sub(width as i64)
            });
            wnaf.extend(core::iter::repeat_n(0, window - 1));
            pos += window;
        }
    }

    // If there is a remaining carry (the scalar used all `bit_len` bit and the last wNAF digit was
    // negative), emit it so the representation is exact.
    if carry != 0 {
        wnaf.push(carry as i64);
    }
}

/// Performs w-NAF exponentiation with the provided window table and w-NAF form scalar.
///
/// This function must be provided a `table` and `wnaf` that were constructed with
/// the same window size; otherwise, it may panic or produce invalid results.
#[inline]
fn wnaf_exp<G: Group>(table: &[G], wnaf: &[i64]) -> G {
    wnaf_multi_exp(&[table], &[wnaf])
}

/// Performs w-NAF multi-exponentiation using the interleaved window method, also known as
/// Straus' method.
///
/// The key insight is that when computing this sum by means of additions and doublings, the
/// doublings can be shared by performing the additions within an inner loop.
///
/// This function must be provided with `tables` and `wnafs` that were constructed with
/// the same window size; otherwise, it may panic or produce invalid results.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
fn wnaf_multi_exp<G: Group, T: AsRef<[G]>, W: AsRef<[i64]>>(tables: &[T], wnafs: &[W]) -> G {
    debug_assert_eq!(tables.len(), wnafs.len());
    let window_size = wnafs.iter().map(|w| w.as_ref().len()).max().unwrap_or(0);

    let mut result = G::identity();
    let mut found_one = false;

    for i in (0..window_size).rev() {
        // Only double once per iteration of the loop
        if found_one {
            result = result.double();
        }

        for (table, wnaf) in tables.iter().zip(wnafs.iter()) {
            let n = wnaf.as_ref().get(i).copied().unwrap_or(0);
            if n != 0 {
                found_one = true;

                if n > 0 {
                    result += table.as_ref()[(n / 2) as usize];
                } else {
                    result -= table.as_ref()[((-n) / 2) as usize];
                }
            }
        }
    }

    result
}

/// Get the little endian representation of a field, namely a scalar.
fn le_repr<F: PrimeField>(fe: &F) -> F::Repr {
    let mut ret = fe.to_repr();
    // TODO(tarcieri): we currently assume this is always big endian. Make it configurable.
    ret.as_mut().reverse();
    ret
}
