#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
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
mod wnaf;

pub use crate::{
    base::WnafBase,
    scalar::WnafScalar,
    traits::{WindowSize, WnafGroup},
};
pub use group::Group;

#[cfg(feature = "alloc")]
pub use crate::wnaf::Wnaf;

use crate::limb_buffer::LimbBuffer;
use ff::PrimeField;

/// Computes a w-NAF window table for the given base and window size.
///
/// For a window of size `w` non-zero w-NAF digits are odd and have magnitude at most `2^(w-1) - 1`.
///
/// The table is indexed by `|digit| / 2`, so the required size is `(2^(w-1) - 1) / 2 + 1 = 2^(w-2)`
/// entries.
fn wnaf_table<G: Group>(table: &mut [G], base: G, window: usize) {
    debug_assert_eq!(table.len(), 1 << (window - 2));

    let dbl = base.double();
    let mut cur = base;

    for entry in table {
        *entry = cur;
        cur.add_assign(&dbl);
    }
}

/// Fills `wnaf` with the w-NAF representation of a little-endian scalar, and returns the
/// number of digits written.
#[allow(clippy::cast_possible_wrap)]
fn wnaf_form<S: AsRef<[u8]>>(wnaf: &mut [i64], c: S, window: usize) -> usize {
    debug_assert!(window >= 2);
    debug_assert!(window <= 64);

    let bit_len = c.as_ref().len() * 8;
    debug_assert!(wnaf.len() > bit_len, "wnaf storage too small");

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

/// Get the little endian representation of a field, namely a scalar.
fn le_repr<F: PrimeField>(fe: &F) -> F::Repr {
    let mut ret = fe.to_repr();
    // TODO(tarcieri): we currently assume this is always big endian. Make it configurable.
    ret.as_mut().reverse();
    ret
}
