//! Vendored subset of the w-NAF implementation from the `group` crate, also forked as the `wnaf`
//! crate in this repo.
//!
//! These types are vendored so we can release `k256` without having to first stabilize `wnaf`. The
//! goal is to eventually get onto the implementation in the `wnaf` crate (and ideally, eventually
//! get onto the implementation in `group`).

use core::{marker::PhantomData, ops::Mul};
use elliptic_curve::{
    array::{
        Array, ArraySize,
        typenum::{U1, U2, U3, U4, U5, U6, U7, U8, U16, U32, U64, Unsigned},
    },
    group::Group,
};
use primeorder::{PrimeField, PrimeFieldExt};

// Compute w-NAF table size using `typenum` type-level arithmetic. Unfortunately we can't use this
// in struct definitions or bounds without the compiler infinitely recursing.
// TODO(tarcieri): either make use of this or remove it when copying this back to `wnaf` crate
//type TableSize<W> = Shleft<U1, Diff<W, U2>>;

/// Allowed w-NAF window size: we use this to precompute the window point sizes, because it's
/// currently not possible to write bounds for them.
pub(super) trait WindowSize: Unsigned {
    /// Number of precomputed points in the window table: `1 << (Self::USIZE - 2)`.
    type TableSize: ArraySize;
}

// TODO(tarcieri): compute or failing that test window sizes
macro_rules! impl_window_sizes {
    ($($window_size:ty => $table_size:ty),+) => {
        $(
            impl WindowSize for $window_size {
                type TableSize = $table_size;
            }
        )+
    };
}

impl_window_sizes!(U2 => U1, U3 => U2, U4 => U4, U5 => U8, U6 => U16, U7 => U32, U8 => U64);

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
pub(super) struct WnafBase<G: Group, W: WindowSize> {
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

/// A "w-ary non-adjacent form" scalar, precomputed to improve the speed of scalar multiplication.
///
/// # Examples
///
/// See [`WnafBase`] for usage examples.
#[derive(Clone, Debug)]
pub(super) struct WnafScalar<F: PrimeField, W: WindowSize, WnafStorage: ArraySize> {
    wnaf: Array<i64, WnafStorage>,
    digits: usize,
    _field: PhantomData<(F, W)>,
}

impl<F: PrimeFieldExt, W: WindowSize, WnafStorage: ArraySize> WnafScalar<F, W, WnafStorage> {
    /// Computes the w-NAF representation of the given scalar with window size `W`.
    pub fn new(scalar: &F) -> Self {
        let mut wnaf = Array::from_fn(|_| 0i64);
        let len = wnaf_form(&mut wnaf, scalar.to_le_repr(), W::USIZE);
        WnafScalar {
            wnaf,
            digits: len,
            _field: PhantomData,
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
    /// Returns `None` if `bytes` is longer than the field's canonical representation, if the
    /// encoded integer is greater than or equal to the field modulus, or if `bytes.len() * 8 + 1`
    /// exceeds `WnafStorage::USIZE` (which would overflow the fixed-size `wnaf` storage).
    pub fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() * 8 + 1 > WnafStorage::USIZE {
            return None;
        }

        // Validate that `bytes` encodes a canonical field element by round-tripping it through
        // `F::from_repr`, which returns `None` for any integer >= the modulus.
        //
        // `from_repr` consumes the canonical big-endian representation, so reverse the
        // little-endian input into a zero-extended `F::Repr`.
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

        let mut wnaf = Array::default();
        let digits = wnaf_form(&mut wnaf, bytes, W::USIZE);

        Some(WnafScalar {
            wnaf,
            digits,
            _field: PhantomData,
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
    fn new(buf: &'a [u8]) -> Self {
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

    fn increment_limb(&mut self) {
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

    fn get(&mut self, idx: usize) -> (u64, u64) {
        assert!([self.cur_idx, self.cur_idx + 1].contains(&idx));
        if idx > self.cur_idx {
            self.increment_limb();
        }
        (self.cur_limb, self.next_limb)
    }
}

/// Computes a w-NAF window table for the given base and window size.
///
/// For a window of size `w` non-zero w-NAF digits are odd and have magnitude at most `2^(w-1) - 1`.
///
/// The table is indexed by `|digit| / 2`, so the required size is `(2^(w-1) - 1) / 2 + 1 = 2^(w-2)`
/// entries.
fn wnaf_table<G: Group, TableSize: ArraySize>(base: G, window: usize) -> Array<G, TableSize> {
    debug_assert_eq!(TableSize::USIZE, 1 << (window - 2));

    let dbl = base.double();
    let mut cur = base;

    Array::from_fn(|_| {
        let entry = cur;
        cur.add_assign(&dbl);
        entry
    })
}

/// Fills `wnaf` with the w-NAF representation of a little-endian scalar, and returns the
/// number of digits written.
#[allow(clippy::cast_possible_wrap)]
fn wnaf_form<S: AsRef<[u8]>, WnafStorage: ArraySize>(
    wnaf: &mut Array<i64, WnafStorage>,
    c: S,
    window: usize,
) -> usize {
    // Required by the NAF definition.
    debug_assert!(window >= 2);
    // Required so that the NAF digits fit in i64.
    debug_assert!(window <= 64);

    let bit_len = c.as_ref().len() * 8;
    debug_assert!(WnafStorage::USIZE > bit_len, "wnaf storage too small");

    let width = 1u64 << window;
    let window_mask = width - 1;

    let mut limbs = LimbBuffer::new(c.as_ref());
    let mut pos = 0;
    let mut carry = 0;
    let mut cursor = 0;

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
            // If carry == 0 and window_val & 1 == 0, then the next carry should be 0.
            // If carry == 1 and window_val & 1 == 0, then bit_buf & 1 == 1 so the next carry should
            // be 1.
            wnaf[cursor] = 0;
            cursor += 1;
            pos += 1;
        } else {
            wnaf[cursor] = if window_val < width / 2 {
                carry = 0;
                window_val as i64
            } else {
                carry = 1;
                (window_val as i64).wrapping_sub(width as i64)
            };
            cursor += 1;
            for _ in 1..window {
                wnaf[cursor] = 0;
                cursor += 1;
            }
            pos += window;
        }
    }

    // If there is a remaining carry (the scalar used all `bit_len` bits and the last w-NAF digit
    // was negative), emit it so the representation is exact.
    if carry != 0 {
        wnaf[cursor] = carry as i64;
        cursor += 1;
    }

    cursor
}

/// Performs w-NAF exponentiation with the provided window table and w-NAF form scalar.
///
/// `window` must match the window size used to construct both `table` and `wnaf`.
#[inline]
fn wnaf_exp<G: Group, TableSize: ArraySize, WnafStorage: ArraySize>(
    table: &Array<G, TableSize>,
    wnaf: &Array<i64, WnafStorage>,
    wnaf_len: usize,
) -> G {
    let terms = [(table.as_slice(), wnaf.as_slice(), wnaf_len)];
    wnaf_multi_exp(terms.iter().copied())
}

/// Performs w-NAF multi-exponentiation using the interleaved window method, also known as
/// Straus's method.
///
/// The key insight is that when computing this sum by means of additions and doublings, the
/// doublings can be shared by performing the additions within an inner loop.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
fn wnaf_multi_exp<'a, G, I>(terms: I) -> G
where
    G: Group,
    I: Clone + IntoIterator<Item = (&'a [G], &'a [i64], usize)>,
{
    let window_size = terms
        .clone()
        .into_iter()
        .map(|(_, _, len)| len)
        .max()
        .unwrap_or(0);

    let mut result = G::identity();
    let mut found_one = false;

    for i in (0..window_size).rev() {
        if found_one {
            result = result.double();
        }

        for (table, wnaf, _) in terms.clone() {
            let n = wnaf.get(i).copied().unwrap_or(0);

            if n != 0 {
                found_one = true;

                if n > 0 {
                    result += table[(n / 2) as usize];
                } else {
                    result -= table[((-n) / 2) as usize];
                }
            }
        }
    }

    result
}
