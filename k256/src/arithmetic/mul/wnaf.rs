//! Vendored subset of the w-NAF implementation from the `group` crate, also forked as the `wnaf`
//! crate in this repo.
//!
//! These types are vendored so we can release `k256` without having to first stabilize `wnaf`. The
//! goal is to eventually get onto the implementation in the `wnaf` crate (and ideally, eventually
//! get onto the implementation in `group`).

use alloc::vec::Vec;
use core::{marker::PhantomData, ops::Mul};
use elliptic_curve::group::Group;
use primeorder::{PrimeField, PrimeFieldExt};

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
pub(super) struct WnafBase<G: Group, const WINDOW_SIZE: usize> {
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
    #[must_use]
    pub fn multiscalar_mul<const N: usize>(
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

/// A "w-ary non-adjacent form" scalar, that uses precomputation to improve the speed of
/// scalar multiplication.
///
/// # Examples
///
/// See [`WnafBase`] for usage examples.
#[derive(Clone, Debug)]
pub(super) struct WnafScalar<F: PrimeField, const WINDOW_SIZE: usize> {
    pub(crate) wnaf: Vec<i64>,
    field: PhantomData<F>,
}

impl<F: PrimeFieldExt, const WINDOW_SIZE: usize> WnafScalar<F, WINDOW_SIZE> {
    /// Computes the w-NAF representation of the given scalar with the specified
    /// `WINDOW_SIZE`.
    pub fn new(scalar: &F) -> Self {
        let mut wnaf = vec![];

        // Compute the w-NAF form of the scalar.
        wnaf_form(&mut wnaf, scalar.to_le_repr(), WINDOW_SIZE);

        WnafScalar {
            wnaf,
            field: PhantomData,
        }
    }

    /// Computes the w-NAF representation directly from raw little-endian bytes.
    ///
    /// `bytes` is interpreted as a little-endian unsigned integer (trailing zero bytes may be
    /// omitted), and the resulting [`WnafScalar`] evaluates to that integer times the base.
    /// Because the number of w-NAF digits — and therefore the number of doublings in the
    /// evaluation loop — is proportional to `bytes.len() * 8`, passing a slice shorter than the
    /// field's canonical representation produces a faster scalar.
    ///
    /// This is intended for callers that have already decomposed a scalar into a value smaller
    /// than the field modulus, e.g. the ~128-bit half-scalars produced by a GLV endomorphism
    /// decomposition.
    ///
    /// The encoded integer is validated to be a canonical field element: it must be strictly
    /// less than the field modulus. No modular reduction is performed — a value that is not
    /// already in range is rejected rather than reduced, so the returned [`WnafScalar`] always
    /// evaluates to the integer `bytes` encodes.
    ///
    /// # Errors
    ///
    /// Returns `None` if `bytes` is longer than the field's canonical representation, or if
    /// the encoded integer is greater than or equal to the field modulus.
    pub fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        // Validate that `bytes` encodes a canonical field element by round-tripping it through
        // `F::from_repr`, which returns `None` for any integer greater than or equal to the
        // modulus. `from_repr` consumes the canonical representation, assumed big-endian to match
        // `le_repr` below, so reverse the little-endian input into a zero-extended `F::Repr`.
        let mut repr = F::Repr::default();
        let repr_len = repr.as_ref().len();

        // Anything wider than the canonical representation is necessarily out of range.
        if bytes.len() > repr_len {
            return None;
        }

        for (i, &byte) in bytes.iter().enumerate() {
            repr.as_mut()[repr_len - 1 - i] = byte;
        }

        if bool::from(F::from_repr(repr).is_none()) {
            return None;
        }

        let mut wnaf = vec![];

        // Compute the w-NAF form directly from the provided little-endian bytes.
        wnaf_form(&mut wnaf, bytes, WINDOW_SIZE);

        Some(WnafScalar {
            wnaf,
            field: PhantomData,
        })
    }
}

/// This struct represents a view of a sequence of bytes as a sequence of
/// `u64` limbs in little-endian byte order. It maintains a current index, and
/// allows access to the limb at that index and the one following it. Bytes
/// beyond the end of the original buffer are treated as zero.
struct LimbBuffer<'a> {
    buf: &'a [u8],
    cur_idx: usize,
    cur_limb: u64,
    next_limb: u64,
}

impl<'a> LimbBuffer<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        let mut ret = Self {
            buf,
            cur_idx: 0,
            cur_limb: 0,
            next_limb: 0,
        };

        // Initialise the limb buffers.
        ret.increment_limb();
        ret.increment_limb();
        ret.cur_idx = 0usize;

        ret
    }

    pub(crate) fn increment_limb(&mut self) {
        self.cur_idx += 1;
        self.cur_limb = self.next_limb;
        match self.buf.len() {
            // There are no more bytes in the buffer; zero-extend.
            0 => self.next_limb = 0,

            // There are fewer bytes in the buffer than a u64 limb; zero-extend.
            x @ 1..=7 => {
                let mut next_limb = [0; 8];
                next_limb[..x].copy_from_slice(self.buf);
                self.next_limb = u64::from_le_bytes(next_limb);
                self.buf = &[];
            }

            // There are at least eight bytes in the buffer; read the next u64 limb.
            _ => {
                let (next_limb, rest) = self.buf.split_at(8);
                self.next_limb = u64::from_le_bytes([
                    next_limb[0],
                    next_limb[1],
                    next_limb[2],
                    next_limb[3],
                    next_limb[4],
                    next_limb[5],
                    next_limb[6],
                    next_limb[7],
                ]);
                self.buf = rest;
            }
        }
    }

    pub(crate) fn get(&mut self, idx: usize) -> (u64, u64) {
        assert!([self.cur_idx, self.cur_idx + 1].contains(&idx));
        if idx > self.cur_idx {
            self.increment_limb();
        }
        (self.cur_limb, self.next_limb)
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
