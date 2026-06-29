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
use ff::PrimeField;

/// Type used to represent w-NAF digits.
///
/// For a window of size `w` non-zero w-NAF digits are odd and have magnitude at most `2^(w-1) - 1`
/// and lie within `{-(2^(w-1)-1), 2^(w-1)-1}`.
pub type Digit = i8;

/// Maximum supported value for `w`.
///
/// This ensures `2^(8-1)-1=127`, so digits lie within `{-127,127}`, which fits in `i8`.
// NOTE: this is also the maximum impl size we support for the `WindowSize` trait
pub const W_MAX: usize = 8;

/// Computes a w-NAF window table for the given base and window size.
///
/// For a window of size `w` non-zero w-NAF digits are odd and have magnitude at most `2^(w-1) - 1`.
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

/// Fills `wnaf` with the w-NAF representation of a little-endian scalar, and returns the
/// number of digits written.
#[allow(clippy::cast_possible_wrap)]
fn wnaf_form<S: AsRef<[u8]>>(wnaf: &mut [Digit], c: S, bit_len: usize, window: usize) -> usize {
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
            wnaf[cursor] = if window_val < width / 2 {
                carry = 0;
                window_val as Digit
            } else {
                carry = 1;
                (window_val as Digit).wrapping_sub(width as Digit)
            };
            cursor += 1;

            let max_pos = bit_len.saturating_sub(carry as usize);
            let skip = window.min(max_pos - pos);

            for _ in 1..skip {
                wnaf[cursor] = 0;
                cursor += 1;
            }
            pos += skip;
        }
    }

    // If there is a remaining carry (the scalar used all `bit_len` bits and the last w-NAF digit
    // was negative), emit it so the representation is exact.
    if carry != 0 {
        wnaf[cursor] = carry as Digit;
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

#[cfg(test)]
mod tests {
    use super::{Digit, wnaf_form};
    use alloc::vec::Vec;

    /// Reconstruct the integer value encoded by a w-NAF digit sequence.
    ///
    /// `value = Σ digits[i] * 2^i`
    fn reconstruct(digits: &[Digit]) -> i128 {
        digits
            .iter()
            .enumerate()
            .map(|(i, &d)| (d as i128) * (1i128 << i))
            .sum()
    }

    /// Run `wnaf_form` on little-endian `bytes` with the given window size and return only the
    /// written digits (the rest of the buffer is discarded).
    fn run(bytes: &[u8], window: usize) -> Vec<Digit> {
        let bit_len = bytes.len() * 8;
        // `+2`: one so `bit_len < buf.len()` (the debug_assert inside wnaf_form is satisfied),
        // one more for any carry digit that may be emitted past `bit_len`.
        let mut buf = vec![0i8; bit_len + 2];
        let n = wnaf_form(&mut buf, bytes, bit_len, window);
        buf.truncate(n);
        buf
    }

    // ── zero scalar ─────────────────────────────────────────────────────────

    #[test]
    fn scalar_zero() {
        // No bytes → no digits written.
        assert_eq!(run(&[], 2), &[]);
        assert_eq!(run(&[], 5), &[]);
    }

    // ── single non-zero digit (no borrowing) ────────────────────────────────

    #[test]
    fn scalar_one_w2() {
        let d = run(&[0x01], 2);
        assert_eq!(reconstruct(&d), 1);
        assert_eq!(d[0], 1);
        assert!(d[1..].iter().all(|&x| x == 0));
    }

    // ── borrowing / negative digit ───────────────────────────────────────────

    #[test]
    fn scalar_three_w2() {
        // 3 = 0b11  →  -1·1 + 1·4  →  NAF = [-1, 0, 1, 0, …]
        let d = run(&[0x03], 2);
        assert_eq!(reconstruct(&d), 3);
        assert_eq!(&d[..4], &[-1, 0, 1, 0]);
    }

    // ── two non-adjacent non-zero digits ────────────────────────────────────

    #[test]
    fn scalar_five_w2() {
        // 5 = 0b101  →  1·1 + 1·4  →  NAF w=2 = [1, 0, 1, 0, …]
        let d = run(&[0x05], 2);
        assert_eq!(reconstruct(&d), 5);
        assert_eq!(&d[..4], &[1, 0, 1, 0]);
    }

    #[test]
    fn scalar_five_w3() {
        // 5 fits in one w=3 digit (magnitude ≤ 2^(3-1)-1 = 3 … wait, 5 > 3).
        // Actually for w=3: width=8, digits in (-7..=7) odd, window_val=5 < 4? No, 5>=4.
        // So: 5 → digit = 5-8 = -3 at pos 0, carry=1 → digit = 1 at pos 3.
        // But that's the same as checking via reconstruct.
        // In fact for w=3, 5 < width/2=4 is false, so this DOES borrow:
        // NAF w=3 of 5 = [-3, 0, 0, 1, …]? Let me re-derive.
        //   pos=0: window_val=5, >=4, digit=5-8=-3, carry=1, skip=3 → pos=3
        //   pos=3: carry=1, bit_buf=5>>3=0, window_val=1, <4, digit=1, carry=0 → pos=6
        //   NAF = [-3, 0, 0, 1, 0, 0, …]  value = -3 + 8 = 5 ✓
        let d = run(&[0x05], 3);
        assert_eq!(reconstruct(&d), 5);
        assert_eq!(&d[..4], &[-3, 0, 0, 1]);
    }

    // ── borrow chain ────────────────────────────────────────────────────────

    #[test]
    fn scalar_seven_w2() {
        // 7 = 0b111  →  -1·1 + 1·8  →  NAF w=2 = [-1, 0, 0, 1, …]
        let d = run(&[0x07], 2);
        assert_eq!(reconstruct(&d), 7);
        assert_eq!(&d[..4], &[-1, 0, 0, 1]);
    }

    #[test]
    fn scalar_seven_w3() {
        // Same value, wider window — same structure for this scalar.
        let d = run(&[0x07], 3);
        assert_eq!(reconstruct(&d), 7);
        assert_eq!(&d[..4], &[-1, 0, 0, 1]);
    }

    // ── large negative digit with wider window ───────────────────────────────

    #[test]
    fn scalar_eleven_w4() {
        // 11 = 0b1011  →  -5·1 + 1·16  →  NAF w=4 = [-5, 0, 0, 0, 1, 0, 0, 0]
        let d = run(&[0x0b], 4);
        assert_eq!(reconstruct(&d), 11);
        assert_eq!(&d[..8], &[-5, 0, 0, 0, 1, 0, 0, 0]);
    }

    // ── alternating bits (no borrow for w=2) ────────────────────────────────

    #[test]
    fn scalar_21_w2() {
        // 21 = 0b10101  →  all individual set bits are non-adjacent  →  no borrow
        // NAF w=2 = [1, 0, 1, 0, 1, 0, …]
        let d = run(&[0x15], 2);
        assert_eq!(reconstruct(&d), 21);
        assert_eq!(&d[..6], &[1, 0, 1, 0, 1, 0]);
    }

    #[test]
    fn scalar_21_w3() {
        // 21 = 0b10101  →  window_val at pos 0: 21 & 7 = 5 ≥ 4, digit = 5-8 = -3, carry=1
        // then pos 3: carry+bit = 1+(21>>3 & 7) = 1+2 = 3 < 4, digit = 3
        // NAF w=3 = [-3, 0, 0, 3, 0, 0, …]  value = -3 + 3·8 = 21 ✓
        let d = run(&[0x15], 3);
        assert_eq!(reconstruct(&d), 21);
        assert_eq!(&d[..6], &[-3, 0, 0, 3, 0, 0]);
    }

    // ── carry propagation beyond bit_len ────────────────────────────────────

    #[test]
    fn scalar_0xff_carry_extra_digit() {
        // 0xFF = 255 = 0b1111_1111
        // The borrow at pos 0 propagates through all 8 bits, emitting a carry digit at pos 8.
        // NAF w=2 = [-1, 0, 0, 0, 0, 0, 0, 0, 1]  value = -1 + 256 = 255 ✓
        let d = run(&[0xFF], 2);
        assert_eq!(reconstruct(&d), 255);
        assert_eq!(&d[..9], &[-1, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    // ── cross-byte carry ─────────────────────────────────────────────────────

    #[test]
    fn scalar_511_cross_byte_carry() {
        // 511 = 0x1FF = 0b1_1111_1111
        // bytes (LE) = [0xFF, 0x01]  →  u64 limb = 0x01FF
        // Borrow at pos 0 ripples across the byte boundary, resolving at pos 9.
        // NAF w=2 = [-1, 0, 0, 0, 0, 0, 0, 0, 0, 1, …]  value = -1 + 512 = 511 ✓
        let d = run(&[0xFF, 0x01], 2);
        assert_eq!(reconstruct(&d), 511);
        assert_eq!(&d[..10], &[-1, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn scalar_256_no_carry() {
        // 256 = 0x100, bytes (LE) = [0x00, 0x01]
        // Single set bit at position 8 — no borrowing.
        // NAF w=2 = [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, …]
        let d = run(&[0x00, 0x01], 2);
        assert_eq!(reconstruct(&d), 256);
        assert_eq!(&d[..10], &[0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    }

    // ── all window sizes agree on value ─────────────────────────────────────

    #[test]
    fn all_windows_agree_on_value() {
        // These scalars exercise carry, multi-byte input, and alternating patterns.
        let cases: &[(&[u8], i128)] = &[
            (&[0x01], 1),
            (&[0x07], 7),
            (&[0x0F], 15),
            (&[0x15], 21),
            (&[0x7F], 127),
            (&[0xAB], 0xAB),
            (&[0xFF], 255),
            (&[0xFF, 0x01], 511),
            (&[0x00, 0x01], 256),
        ];
        for &(bytes, expected) in cases {
            for window in 2..=8usize {
                let d = run(bytes, window);
                assert_eq!(
                    reconstruct(&d),
                    expected,
                    "scalar={expected:#x} window={window}"
                );
            }
        }
    }
}

/// Get the little endian representation of a field, namely a scalar.
fn le_repr<F: PrimeField>(fe: &F) -> F::Repr {
    let mut ret = fe.to_repr();
    // TODO(tarcieri): determine endianness via `PrimeField` trait. See zkcrypto/rfcs#4
    ret.as_mut().reverse();
    ret
}
