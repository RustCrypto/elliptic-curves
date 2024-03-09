//! 32-bit secp256r1 scalar field algorithms.

use super::MODULUS;
use crate::{
    arithmetic::util::{adc, mac, sbb},
    U256,
};

/// MU = floor(2^512 / n)
///    = 115792089264276142090721624801893421302707618245269942344307673200490803338238
///    = 0x100000000fffffffffffffffeffffffff43190552df1a6c21012ffd85eedf9bfe
const MU: [u32; 9] = [
    0xeedf_9bfe,
    0x012f_fd85,
    0xdf1a_6c21,
    0x4319_0552,
    0xffff_ffff,
    0xffff_fffe,
    0xffff_ffff,
    0x0000_0000,
    0x0000_0001,
];

/// Barrett Reduction
///
/// The general algorithm is:
/// ```text
/// p = n = order of group
/// b = 2^64 = 64bit machine word
/// k = 4
/// a \in [0, 2^512]
/// mu := floor(b^{2k} / p)
/// q1 := floor(a / b^{k - 1})
/// q2 := q1 * mu
/// q3 := <- floor(a / b^{k - 1})
/// r1 := a mod b^{k + 1}
/// r2 := q3 * m mod b^{k + 1}
/// r := r1 - r2
///
/// if r < 0: r := r + b^{k + 1}
/// while r >= p: do r := r - p (at most twice)
/// ```
///
/// References:
/// - Handbook of Applied Cryptography, Chapter 14
///   Algorithm 14.42
///   http://cacr.uwaterloo.ca/hac/about/chap14.pdf
///
/// - Efficient and Secure Elliptic Curve Cryptography Implementation of Curve P-256
///   Algorithm 6) Barrett Reduction modulo p
///   https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session6-adalier-mehmet.pdf
#[inline]
#[allow(clippy::too_many_arguments)]
pub(super) const fn barrett_reduce(lo: U256, hi: U256) -> U256 {
    let lo = lo.as_words();
    let hi = hi.as_words();

    let a0 = lo[0];
    let a1 = lo[1];
    let a2 = lo[2];
    let a3 = lo[3];
    let a4 = lo[4];
    let a5 = lo[5];
    let a6 = lo[6];
    let a7 = lo[7];
    let a8 = hi[0];
    let a9 = hi[1];
    let a10 = hi[2];
    let a11 = hi[3];
    let a12 = hi[4];
    let a13 = hi[5];
    let a14 = hi[6];
    let a15 = hi[7];

    let q1: [u32; 9] = [a7, a8, a9, a10, a11, a12, a13, a14, a15];
    let q3: [u32; 9] = q1_times_mu_shift_nine(&q1);

    let r1: [u32; 9] = [a0, a1, a2, a3, a4, a5, a6, a7, a8];
    let r2: [u32; 9] = q3_times_n_keep_nine(&q3);
    let r: [u32; 9] = sub_inner_nine(r1, r2);

    // Result is in range (0, 3*n - 1),
    // and 90% of the time, no subtraction will be needed.
    let r = subtract_n_if_necessary(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]);
    let r = subtract_n_if_necessary(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]);

    U256::from_words([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]])
}

const fn q1_times_mu_shift_nine(q1: &[u32; 9]) -> [u32; 9] {
    // Schoolbook multiplication

    let (_w0, carry) = mac(0, q1[0], MU[0], 0);
    let (w1, carry) = mac(0, q1[0], MU[1], carry);
    let (w2, carry) = mac(0, q1[0], MU[2], carry);
    let (w3, carry) = mac(0, q1[0], MU[3], carry);
    let (w4, carry) = mac(0, q1[0], MU[4], carry);
    let (w5, carry) = mac(0, q1[0], MU[5], carry);
    let (w6, carry) = mac(0, q1[0], MU[6], carry);
    // NOTE MU[7] == 0
    // let (w7, carry) = mac(0, q1[0], MU[7], carry);
    let (w7, _carry) = (carry, 0);
    // NOTE MU[8] == 1
    // let (w8, w9) = mac(0, q1[0], MU[8], carry);
    let (w8, w9) = (q1[0], 0);

    let (_w1, carry) = mac(w1, q1[1], MU[0], 0);
    let (w2, carry) = mac(w2, q1[1], MU[1], carry);
    let (w3, carry) = mac(w3, q1[1], MU[2], carry);
    let (w4, carry) = mac(w4, q1[1], MU[3], carry);
    let (w5, carry) = mac(w5, q1[1], MU[4], carry);
    let (w6, carry) = mac(w6, q1[1], MU[5], carry);
    let (w7, carry) = mac(w7, q1[1], MU[6], carry);
    // NOTE MU[7] == 0
    // let (w8, carry) = mac(w8, q1[1], MU[7], carry);
    let (w8, carry) = adc(w8, 0, carry);
    // NOTE MU[8] == 1
    // let (w9, w10) = mac(w9, q1[1], MU[8], carry);
    let (w9, w10) = adc(w9, q1[1], carry);

    let (_w2, carry) = mac(w2, q1[2], MU[0], 0);
    let (w3, carry) = mac(w3, q1[2], MU[1], carry);
    let (w4, carry) = mac(w4, q1[2], MU[2], carry);
    let (w5, carry) = mac(w5, q1[2], MU[3], carry);
    let (w6, carry) = mac(w6, q1[2], MU[4], carry);
    let (w7, carry) = mac(w7, q1[2], MU[5], carry);
    let (w8, carry) = mac(w8, q1[2], MU[6], carry);
    // let (w9, carry) = mac(w9, q1[2], MU[7], carry);
    let (w9, carry) = adc(w9, 0, carry);
    // let (w10, w11) = mac(w10, q1[2], MU[8], carry);
    let (w10, w11) = adc(w10, q1[2], carry);

    let (_w3, carry) = mac(w3, q1[3], MU[0], 0);
    let (w4, carry) = mac(w4, q1[3], MU[1], carry);
    let (w5, carry) = mac(w5, q1[3], MU[2], carry);
    let (w6, carry) = mac(w6, q1[3], MU[3], carry);
    let (w7, carry) = mac(w7, q1[3], MU[4], carry);
    let (w8, carry) = mac(w8, q1[3], MU[5], carry);
    let (w9, carry) = mac(w9, q1[3], MU[6], carry);
    // let (w10, carry) = mac(w10, q1[3], MU[7], carry);
    let (w10, carry) = adc(w10, 0, carry);
    // let (w11, w12) = mac(w11, q1[3], MU[8], carry);
    let (w11, w12) = adc(w11, q1[3], carry);

    let (_w4, carry) = mac(w4, q1[4], MU[0], 0);
    let (w5, carry) = mac(w5, q1[4], MU[1], carry);
    let (w6, carry) = mac(w6, q1[4], MU[2], carry);
    let (w7, carry) = mac(w7, q1[4], MU[3], carry);
    let (w8, carry) = mac(w8, q1[4], MU[4], carry);
    let (w9, carry) = mac(w9, q1[4], MU[5], carry);
    let (w10, carry) = mac(w10, q1[4], MU[6], carry);
    // let (w11, carry) = mac(w11, q1[4], MU[7], carry);
    let (w11, carry) = adc(w11, 0, carry);
    // let (w12, w13) = mac(w12, q1[4], MU[8], carry);
    let (w12, w13) = adc(w12, q1[4], carry);

    let (_w5, carry) = mac(w5, q1[5], MU[0], 0);
    let (w6, carry) = mac(w6, q1[5], MU[1], carry);
    let (w7, carry) = mac(w7, q1[5], MU[2], carry);
    let (w8, carry) = mac(w8, q1[5], MU[3], carry);
    let (w9, carry) = mac(w9, q1[5], MU[4], carry);
    let (w10, carry) = mac(w10, q1[5], MU[5], carry);
    let (w11, carry) = mac(w11, q1[5], MU[6], carry);
    // let (w12, carry) = mac(w12, q1[5], MU[7], carry);
    let (w12, carry) = adc(w12, 0, carry);
    // let (w13, w14) = mac(w13, q1[5], MU[8], carry);
    let (w13, w14) = adc(w13, q1[5], carry);

    let (_w6, carry) = mac(w6, q1[6], MU[0], 0);
    let (w7, carry) = mac(w7, q1[6], MU[1], carry);
    let (w8, carry) = mac(w8, q1[6], MU[2], carry);
    let (w9, carry) = mac(w9, q1[6], MU[3], carry);
    let (w10, carry) = mac(w10, q1[6], MU[4], carry);
    let (w11, carry) = mac(w11, q1[6], MU[5], carry);
    let (w12, carry) = mac(w12, q1[6], MU[6], carry);
    // let (w13, carry) = mac(w13, q1[6], MU[7], carry);
    let (w13, carry) = adc(w13, 0, carry);
    // let (w14, w15) = mac(w14, q1[6], MU[8], carry);
    let (w14, w15) = adc(w14, q1[6], carry);

    let (_w7, carry) = mac(w7, q1[7], MU[0], 0);
    let (w8, carry) = mac(w8, q1[7], MU[1], carry);
    let (w9, carry) = mac(w9, q1[7], MU[2], carry);
    let (w10, carry) = mac(w10, q1[7], MU[3], carry);
    let (w11, carry) = mac(w11, q1[7], MU[4], carry);
    let (w12, carry) = mac(w12, q1[7], MU[5], carry);
    let (w13, carry) = mac(w13, q1[7], MU[6], carry);
    // let (w14, carry) = mac(w14, q1[7], MU[7], carry);
    let (w14, carry) = adc(w14, 0, carry);
    // let (w15, w16) = mac(w15, q1[7], MU[8], carry);
    let (w15, w16) = adc(w15, q1[7], carry);

    let (_w8, carry) = mac(w8, q1[8], MU[0], 0);
    let (w9, carry) = mac(w9, q1[8], MU[1], carry);
    let (w10, carry) = mac(w10, q1[8], MU[2], carry);
    let (w11, carry) = mac(w11, q1[8], MU[3], carry);
    let (w12, carry) = mac(w12, q1[8], MU[4], carry);
    let (w13, carry) = mac(w13, q1[8], MU[5], carry);
    let (w14, carry) = mac(w14, q1[8], MU[6], carry);
    // let (w15, carry) = mac(w15, q1[8], MU[7], carry);
    let (w15, carry) = adc(w15, 0, carry);
    // let (w16, w17) = mac(w16, q1[8], MU[8], carry);
    let (w16, w17) = adc(w16, q1[8], carry);

    // let q2 = [_w0, _w1, _w2, _w3, _w4, _w5, _w6, _w7, _w8, w9, w10, w11, w12, w13, w14, w15, w16, w17];
    [w9, w10, w11, w12, w13, w14, w15, w16, w17]
}

const fn q3_times_n_keep_nine(q3: &[u32; 9]) -> [u32; 9] {
    // Schoolbook multiplication

    let modulus = MODULUS.as_words();

    /* NOTE
     * modulus[7] = 2^32 - 1
     * modulus[6] = 0
     * modulus[5] = 2^32 - 1
     * modulus[4] = 2^32 - 1
     */

    let (w0, carry) = mac(0, q3[0], modulus[0], 0);
    let (w1, carry) = mac(0, q3[0], modulus[1], carry);
    let (w2, carry) = mac(0, q3[0], modulus[2], carry);
    let (w3, carry) = mac(0, q3[0], modulus[3], carry);
    let (w4, carry) = mac(0, q3[0], modulus[4], carry);
    let (w5, carry) = mac(0, q3[0], modulus[5], carry);
    // NOTE modulus[6] = 0
    // let (w6, carry) = mac(0, q3[0], modulus[6], carry);
    let (w6, carry) = (carry, 0);
    let (w7, carry) = mac(0, q3[0], modulus[7], carry);
    // let (w8, _) = mac(0, q3[0], 0, carry);
    let (w8, _) = (carry, 0);

    let (w1, carry) = mac(w1, q3[1], modulus[0], 0);
    let (w2, carry) = mac(w2, q3[1], modulus[1], carry);
    let (w3, carry) = mac(w3, q3[1], modulus[2], carry);
    let (w4, carry) = mac(w4, q3[1], modulus[3], carry);
    let (w5, carry) = mac(w5, q3[1], modulus[4], carry);
    let (w6, carry) = mac(w6, q3[1], modulus[5], carry);
    // let (w7, carry) = mac(w7, q3[1], modulus[6], carry);
    let (w7, carry) = adc(w7, 0, carry);
    let (w8, _) = mac(w8, q3[1], modulus[7], carry);

    let (w2, carry) = mac(w2, q3[2], modulus[0], 0);
    let (w3, carry) = mac(w3, q3[2], modulus[1], carry);
    let (w4, carry) = mac(w4, q3[2], modulus[2], carry);
    let (w5, carry) = mac(w5, q3[2], modulus[3], carry);
    let (w6, carry) = mac(w6, q3[2], modulus[4], carry);
    let (w7, carry) = mac(w7, q3[2], modulus[5], carry);
    // let (w8, _) = mac(w8, q3[2], modulus[6], carry);
    let (w8, _) = adc(w8, 0, carry);

    let (w3, carry) = mac(w3, q3[3], modulus[0], 0);
    let (w4, carry) = mac(w4, q3[3], modulus[1], carry);
    let (w5, carry) = mac(w5, q3[3], modulus[2], carry);
    let (w6, carry) = mac(w6, q3[3], modulus[3], carry);
    let (w7, carry) = mac(w7, q3[3], modulus[4], carry);
    let (w8, _) = mac(w8, q3[3], modulus[5], carry);

    let (w4, carry) = mac(w4, q3[4], modulus[0], 0);
    let (w5, carry) = mac(w5, q3[4], modulus[1], carry);
    let (w6, carry) = mac(w6, q3[4], modulus[2], carry);
    let (w7, carry) = mac(w7, q3[4], modulus[3], carry);
    let (w8, _) = mac(w8, q3[4], modulus[4], carry);

    let (w5, carry) = mac(w5, q3[5], modulus[0], 0);
    let (w6, carry) = mac(w6, q3[5], modulus[1], carry);
    let (w7, carry) = mac(w7, q3[5], modulus[2], carry);
    let (w8, _) = mac(w8, q3[5], modulus[3], carry);

    let (w6, carry) = mac(w6, q3[6], modulus[0], 0);
    let (w7, carry) = mac(w7, q3[6], modulus[1], carry);
    let (w8, _) = mac(w8, q3[6], modulus[2], carry);

    let (w7, carry) = mac(w7, q3[7], modulus[0], 0);
    let (w8, _) = mac(w8, q3[7], modulus[1], carry);

    let (w8, _) = mac(w8, q3[8], modulus[0], 0);

    [w0, w1, w2, w3, w4, w5, w6, w7, w8]
}

#[inline]
#[allow(clippy::too_many_arguments)]
const fn sub_inner_nine(l: [u32; 9], r: [u32; 9]) -> [u32; 9] {
    let (w0, borrow) = sbb(l[0], r[0], 0);
    let (w1, borrow) = sbb(l[1], r[1], borrow);
    let (w2, borrow) = sbb(l[2], r[2], borrow);
    let (w3, borrow) = sbb(l[3], r[3], borrow);
    let (w4, borrow) = sbb(l[4], r[4], borrow);
    let (w5, borrow) = sbb(l[5], r[5], borrow);
    let (w6, borrow) = sbb(l[6], r[6], borrow);
    let (w7, borrow) = sbb(l[7], r[7], borrow);
    let (w8, _borrow) = sbb(l[8], r[8], borrow);

    // If underflow occured in the final limb - don't care (= add b^{k+1}).
    [w0, w1, w2, w3, w4, w5, w6, w7, w8]
}

#[inline]
#[allow(clippy::too_many_arguments)]
const fn subtract_n_if_necessary(
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,
    r5: u32,
    r6: u32,
    r7: u32,
    r8: u32,
) -> [u32; 9] {
    let modulus = MODULUS.as_words();

    let (w0, borrow) = sbb(r0, modulus[0], 0);
    let (w1, borrow) = sbb(r1, modulus[1], borrow);
    let (w2, borrow) = sbb(r2, modulus[2], borrow);
    let (w3, borrow) = sbb(r3, modulus[3], borrow);
    let (w4, borrow) = sbb(r4, modulus[4], borrow);
    let (w5, borrow) = sbb(r5, modulus[5], borrow);
    let (w6, borrow) = sbb(r6, modulus[6], borrow);
    let (w7, borrow) = sbb(r7, modulus[7], borrow);
    let (w8, borrow) = sbb(r8, 0, borrow);

    // If underflow occurred in the final limb, borrow = 0xfff...fff, otherwise
    // borrow = 0x000...000. Thus, we use it as a mask to conditionally add
    // the modulus.
    let (w0, carry) = adc(w0, modulus[0] & borrow, 0);
    let (w1, carry) = adc(w1, modulus[1] & borrow, carry);
    let (w2, carry) = adc(w2, modulus[2] & borrow, carry);
    let (w3, carry) = adc(w3, modulus[3] & borrow, carry);
    let (w4, carry) = adc(w4, modulus[4] & borrow, carry);
    let (w5, carry) = adc(w5, modulus[5] & borrow, carry);
    let (w6, carry) = adc(w6, modulus[6] & borrow, carry);
    let (w7, carry) = adc(w7, modulus[7] & borrow, carry);
    let (w8, _carry) = adc(w8, 0, carry);

    [w0, w1, w2, w3, w4, w5, w6, w7, w8]
}
