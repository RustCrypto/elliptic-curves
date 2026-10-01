#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(clippy::int_plus_one, reason = "clearer for our use cases  ")]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

mod base;
mod limb_buffer;
mod scalar;
mod traits;

#[cfg(feature = "alloc")]
mod boxed;

pub use crate::{
    base::WnafBase,
    scalar::WnafScalar,
    traits::{WindowSize, WnafGroup, WnafSize},
};
pub use array;
pub use group::Group;

#[cfg(feature = "alloc")]
pub use crate::boxed::BoxedWnaf;

use crate::limb_buffer::LimbBuffer;
use primefield::PrimeFieldExt;

/// Type used to represent wNAF digits.
///
/// For a window of size `w` non-zero wNAF digits are odd and have magnitude at most `2^(w-1) - 1`
/// and lie within `{-(2^(w-1)-1), 2^(w-1)-1}`.
pub type Digit = i8;

/// Maximum supported value for `w`.
///
/// This ensures `2^(8-1)-1=127`, so digits lie within `{-127,127}`, which fits in `i8`.
// NOTE: this is also the maximum impl size we support for the `WindowSize` trait
pub const W_MAX: usize = 8;

/// Computes a wNAF window table for the given base and window size.
///
/// For a window of size `w` non-zero wNAF digits are odd and have magnitude at most `2^(w-1) - 1`.
///
/// The table is indexed by `|digit| / 2`, so the required size is `(2^(w-1) - 1) / 2 + 1 = 2^(w-2)`
/// entries.
fn wnaf_table<G: Group>(table: &mut [G], base: &G, window: usize) {
    debug_assert_eq!(table.len(), 1 << (window - 2));

    let dbl = base.double();
    let mut cur = *base;

    for entry in table {
        *entry = cur;
        cur.add_assign(&dbl);
    }
}

/// Fills `wnaf` with the wNAF representation of a little-endian scalar, and returns the
/// number of digits written.
#[allow(clippy::cast_possible_wrap)]
fn wnaf_form<S: AsRef<[u8]>>(wnaf: &mut [Digit], c: S, bit_len: usize, window: usize) -> usize {
    fn digit(n: u64) -> Digit {
        #[cfg(debug_assertions)]
        {
            Digit::try_from(n).expect("overflow")
        }
        #[cfg(not(debug_assertions))]
        {
            n as Digit
        }
    }

    debug_assert!(window >= 2);
    debug_assert!(window <= W_MAX);
    debug_assert!(bit_len < wnaf.len(), "wnaf storage too small");
    debug_assert!(c.as_ref().len() <= bit_len.div_ceil(8), "input too large");

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
            if window_val < width / 2 {
                carry = 0;
                wnaf[cursor] = digit(window_val);
            } else {
                carry = 1;
                // `window_val` and `width` can exceed `Digit::MAX` for windows of 7 and 8, but
                // their difference is always below `width / 2`
                wnaf[cursor] = -digit(width - window_val);
            };

            cursor += 1;

            let max_pos = bit_len.saturating_sub(usize::try_from(carry).expect("overflow"));
            let skip = window.min(max_pos - pos);

            for _ in 1..skip {
                wnaf[cursor] = 0;
                cursor += 1;
            }
            pos += skip;
        }
    }

    // If there is a remaining carry (the scalar used all `bit_len` bits and the last wNAF digit
    // was negative), emit it so the representation is exact.
    if carry != 0 {
        wnaf[cursor] = digit(carry);
        cursor += 1;
    }

    cursor
}

/// Performs wNAF multi-exponentiation using the interleaved window method, also known as
/// Straus's method.
///
/// The key insight is that when computing this sum by means of additions and doublings, the
/// doublings can be shared by performing the additions within an inner loop.
fn wnaf_multi_exp<'a, G, I>(terms: I) -> G
where
    G: Group,
    I: Clone + IntoIterator<Item = (&'a [G], &'a [Digit], usize)>,
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

                #[allow(clippy::cast_sign_loss)]
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

/// Get the little endian representation of a field, namely a scalar.
fn le_repr<F: PrimeFieldExt>(fe: &F) -> F::Repr {
    fe.to_le_repr()
}

#[cfg(test)]
mod tests {
    use super::{Digit, W_MAX, wnaf_form};

    /// Evaluate a wNAF digit sequence back into an integer.
    fn eval(wnaf: &[Digit]) -> i128 {
        wnaf.iter()
            .enumerate()
            .map(|(i, &d)| i128::from(d) << i)
            .sum()
    }

    #[test]
    fn wnaf_form_all_windows() {
        let mut inputs = [[0u8; 15]; 68];
        inputs[1] = [0xff; 15];
        inputs[2] = [0x55; 15];
        inputs[3] = [0xaa; 15];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for bytes in &mut inputs[4..] {
            for b in bytes.iter_mut() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *b = state.to_le_bytes()[7];
            }
        }

        for window in 2..=W_MAX {
            for bytes in &inputs {
                let mut wnaf: [Digit; 122] = [0; 122];
                let len = wnaf_form(&mut wnaf, bytes, 120, window);

                let mut padded = [0u8; 16];
                padded[..15].copy_from_slice(bytes);
                let expected = i128::from_le_bytes(padded);
                assert_eq!(eval(&wnaf[..len]), expected, "window {window}");
            }
        }
    }
}
