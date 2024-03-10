//! 32-bit secp256r1 scalar field algorithms.

use super::MODULUS;
use elliptic_curve::bigint::{Limb, U256};

/// MU = floor(2^512 / n)
///    = 115792089264276142090721624801893421302707618245269942344307673200490803338238
///    = 0x100000000fffffffffffffffeffffffff43190552df1a6c21012ffd85eedf9bfe
const MU: [Limb; 9] = [
    Limb::from_u32(0xeedf_9bfe),
    Limb::from_u32(0x012f_fd85),
    Limb::from_u32(0xdf1a_6c21),
    Limb::from_u32(0x4319_0552),
    Limb::from_u32(0xffff_ffff),
    Limb::from_u32(0xffff_fffe),
    Limb::from_u32(0xffff_ffff),
    Limb::from_u32(0x0000_0000),
    Limb::from_u32(0x0000_0001),
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
    let lo = lo.as_limbs();
    let hi = hi.as_limbs();

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

    let q1: [Limb; 9] = [a7, a8, a9, a10, a11, a12, a13, a14, a15];
    let q3: [Limb; 9] = q1_times_mu_shift_nine(&q1);

    let r1: [Limb; 9] = [a0, a1, a2, a3, a4, a5, a6, a7, a8];
    let r2: [Limb; 9] = q3_times_n_keep_nine(&q3);
    let r: [Limb; 9] = sub_inner_nine(r1, r2);

    // Result is in range (0, 3*n - 1),
    // and 90% of the time, no subtraction will be needed.
    let r = subtract_n_if_necessary(r);
    let r = subtract_n_if_necessary(r);

    U256::new([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]])
}

const fn q1_times_mu_shift_nine(q1: &[Limb; 9]) -> [Limb; 9] {
    // Schoolbook multiplication

    let (_w0, carry) = Limb::ZERO.mac(q1[0], MU[0], Limb::ZERO);
    let (w1, carry) = Limb::ZERO.mac(q1[0], MU[1], carry);
    let (w2, carry) = Limb::ZERO.mac(q1[0], MU[2], carry);
    let (w3, carry) = Limb::ZERO.mac(q1[0], MU[3], carry);
    let (w4, carry) = Limb::ZERO.mac(q1[0], MU[4], carry);
    let (w5, carry) = Limb::ZERO.mac(q1[0], MU[5], carry);
    let (w6, carry) = Limb::ZERO.mac(q1[0], MU[6], carry);
    // NOTE MU[7] == 0
    // let (w7, carry) = Limb::ZERO.mac(q1[0], MU[7], carry);
    let (w7, _carry) = (carry, Limb::ZERO);
    // NOTE MU[8] == 1
    // let (w8, w9) = Limb::ZERO.mac(q1[0], MU[8], carry);
    let (w8, w9) = (q1[0], Limb::ZERO);

    let (_w1, carry) = w1.mac(q1[1], MU[0], Limb::ZERO);
    let (w2, carry) = w2.mac(q1[1], MU[1], carry);
    let (w3, carry) = w3.mac(q1[1], MU[2], carry);
    let (w4, carry) = w4.mac(q1[1], MU[3], carry);
    let (w5, carry) = w5.mac(q1[1], MU[4], carry);
    let (w6, carry) = w6.mac(q1[1], MU[5], carry);
    let (w7, carry) = w7.mac(q1[1], MU[6], carry);
    // NOTE MU[7] == 0
    // let (w8, carry) = w8.mac(q1[1], MU[7], carry);
    let (w8, carry) = w8.adc(Limb::ZERO, carry);
    // NOTE MU[8] == 1
    // let (w9, w10) = w9.mac(q1[1], MU[8], carry);
    let (w9, w10) = w9.adc(q1[1], carry);

    let (_w2, carry) = w2.mac(q1[2], MU[0], Limb::ZERO);
    let (w3, carry) = w3.mac(q1[2], MU[1], carry);
    let (w4, carry) = w4.mac(q1[2], MU[2], carry);
    let (w5, carry) = w5.mac(q1[2], MU[3], carry);
    let (w6, carry) = w6.mac(q1[2], MU[4], carry);
    let (w7, carry) = w7.mac(q1[2], MU[5], carry);
    let (w8, carry) = w8.mac(q1[2], MU[6], carry);
    // let (w9, carry) = w9.mac(q1[2], MU[7], carry);
    let (w9, carry) = w9.adc(Limb::ZERO, carry);
    // let (w10, w11) = w10.mac(q1[2], MU[8], carry);
    let (w10, w11) = w10.adc(q1[2], carry);

    let (_w3, carry) = w3.mac(q1[3], MU[0], Limb::ZERO);
    let (w4, carry) = w4.mac(q1[3], MU[1], carry);
    let (w5, carry) = w5.mac(q1[3], MU[2], carry);
    let (w6, carry) = w6.mac(q1[3], MU[3], carry);
    let (w7, carry) = w7.mac(q1[3], MU[4], carry);
    let (w8, carry) = w8.mac(q1[3], MU[5], carry);
    let (w9, carry) = w9.mac(q1[3], MU[6], carry);
    // let (w10, carry) = w10.mac(q1[3], MU[7], carry);
    let (w10, carry) = w10.adc(Limb::ZERO, carry);
    // let (w11, w12) = w11.mac(q1[3], MU[8], carry);
    let (w11, w12) = w11.adc(q1[3], carry);

    let (_w4, carry) = w4.mac(q1[4], MU[0], Limb::ZERO);
    let (w5, carry) = w5.mac(q1[4], MU[1], carry);
    let (w6, carry) = w6.mac(q1[4], MU[2], carry);
    let (w7, carry) = w7.mac(q1[4], MU[3], carry);
    let (w8, carry) = w8.mac(q1[4], MU[4], carry);
    let (w9, carry) = w9.mac(q1[4], MU[5], carry);
    let (w10, carry) = w10.mac(q1[4], MU[6], carry);
    // let (w11, carry) = w11.mac(q1[4], MU[7], carry);
    let (w11, carry) = w11.adc(Limb::ZERO, carry);
    // let (w12, w13) = w12.mac(q1[4], MU[8], carry);
    let (w12, w13) = w12.adc(q1[4], carry);

    let (_w5, carry) = w5.mac(q1[5], MU[0], Limb::ZERO);
    let (w6, carry) = w6.mac(q1[5], MU[1], carry);
    let (w7, carry) = w7.mac(q1[5], MU[2], carry);
    let (w8, carry) = w8.mac(q1[5], MU[3], carry);
    let (w9, carry) = w9.mac(q1[5], MU[4], carry);
    let (w10, carry) = w10.mac(q1[5], MU[5], carry);
    let (w11, carry) = w11.mac(q1[5], MU[6], carry);
    // let (w12, carry) = w12.mac(q1[5], MU[7], carry);
    let (w12, carry) = w12.adc(Limb::ZERO, carry);
    // let (w13, w14) = w13.mac(q1[5], MU[8], carry);
    let (w13, w14) = w13.adc(q1[5], carry);

    let (_w6, carry) = w6.mac(q1[6], MU[0], Limb::ZERO);
    let (w7, carry) = w7.mac(q1[6], MU[1], carry);
    let (w8, carry) = w8.mac(q1[6], MU[2], carry);
    let (w9, carry) = w9.mac(q1[6], MU[3], carry);
    let (w10, carry) = w10.mac(q1[6], MU[4], carry);
    let (w11, carry) = w11.mac(q1[6], MU[5], carry);
    let (w12, carry) = w12.mac(q1[6], MU[6], carry);
    // let (w13, carry) = w13.mac(q1[6], MU[7], carry);
    let (w13, carry) = w13.adc(Limb::ZERO, carry);
    // let (w14, w15) = w14.mac(q1[6], MU[8], carry);
    let (w14, w15) = w14.adc(q1[6], carry);

    let (_w7, carry) = w7.mac(q1[7], MU[0], Limb::ZERO);
    let (w8, carry) = w8.mac(q1[7], MU[1], carry);
    let (w9, carry) = w9.mac(q1[7], MU[2], carry);
    let (w10, carry) = w10.mac(q1[7], MU[3], carry);
    let (w11, carry) = w11.mac(q1[7], MU[4], carry);
    let (w12, carry) = w12.mac(q1[7], MU[5], carry);
    let (w13, carry) = w13.mac(q1[7], MU[6], carry);
    // let (w14, carry) = w14.mac(q1[7], MU[7], carry);
    let (w14, carry) = w14.adc(Limb::ZERO, carry);
    // let (w15, w16) = w15.mac(q1[7], MU[8], carry);
    let (w15, w16) = w15.adc(q1[7], carry);

    let (_w8, carry) = w8.mac(q1[8], MU[0], Limb::ZERO);
    let (w9, carry) = w9.mac(q1[8], MU[1], carry);
    let (w10, carry) = w10.mac(q1[8], MU[2], carry);
    let (w11, carry) = w11.mac(q1[8], MU[3], carry);
    let (w12, carry) = w12.mac(q1[8], MU[4], carry);
    let (w13, carry) = w13.mac(q1[8], MU[5], carry);
    let (w14, carry) = w14.mac(q1[8], MU[6], carry);
    // let (w15, carry) = w15.mac(w15, q1[8], MU[7], carry);
    let (w15, carry) = w15.adc(Limb::ZERO, carry);
    // let (w16, w17) = w16.mac(w16, q1[8], MU[8], carry);
    let (w16, w17) = w16.adc(q1[8], carry);

    // let q2 = [_w0, _w1, _w2, _w3, _w4, _w5, _w6, _w7, _w8, w9, w10, w11, w12, w13, w14, w15, w16, w17];
    [w9, w10, w11, w12, w13, w14, w15, w16, w17]
}

const fn q3_times_n_keep_nine(q3: &[Limb; 9]) -> [Limb; 9] {
    // Schoolbook multiplication

    let modulus = MODULUS.as_limbs();

    /* NOTE
     * modulus[7] = 2^32 - 1
     * modulus[6] = 0
     * modulus[5] = 2^32 - 1
     * modulus[4] = 2^32 - 1
     */

    let (w0, carry) = Limb::ZERO.mac(q3[0], modulus[0], Limb::ZERO);
    let (w1, carry) = Limb::ZERO.mac(q3[0], modulus[1], carry);
    let (w2, carry) = Limb::ZERO.mac(q3[0], modulus[2], carry);
    let (w3, carry) = Limb::ZERO.mac(q3[0], modulus[3], carry);
    let (w4, carry) = Limb::ZERO.mac(q3[0], modulus[4], carry);
    let (w5, carry) = Limb::ZERO.mac(q3[0], modulus[5], carry);
    // NOTE modulus[6] = 0
    // let (w6, carry) = Limb::ZERO.mac(q3[0], modulus[6], carry);
    let (w6, carry) = (carry, Limb::ZERO);
    let (w7, carry) = Limb::ZERO.mac(q3[0], modulus[7], carry);
    // let (w8, _) = Limb::ZERO.mac(q3[0], Limb::ZERO, carry);
    let (w8, _) = (carry, Limb::ZERO);

    let (w1, carry) = w1.mac(q3[1], modulus[0], Limb::ZERO);
    let (w2, carry) = w2.mac(q3[1], modulus[1], carry);
    let (w3, carry) = w3.mac(q3[1], modulus[2], carry);
    let (w4, carry) = w4.mac(q3[1], modulus[3], carry);
    let (w5, carry) = w5.mac(q3[1], modulus[4], carry);
    let (w6, carry) = w6.mac(q3[1], modulus[5], carry);
    // let (w7, carry) = w7.mac(q3[1], modulus[6], carry);
    let (w7, carry) = w7.adc(Limb::ZERO, carry);
    let (w8, _) = w8.mac(q3[1], modulus[7], carry);

    let (w2, carry) = w2.mac(q3[2], modulus[0], Limb::ZERO);
    let (w3, carry) = w3.mac(q3[2], modulus[1], carry);
    let (w4, carry) = w4.mac(q3[2], modulus[2], carry);
    let (w5, carry) = w5.mac(q3[2], modulus[3], carry);
    let (w6, carry) = w6.mac(q3[2], modulus[4], carry);
    let (w7, carry) = w7.mac(q3[2], modulus[5], carry);
    // let (w8, _) = w8.mac(q3[2], modulus[6], carry);
    let (w8, _) = w8.adc(Limb::ZERO, carry);

    let (w3, carry) = w3.mac(q3[3], modulus[0], Limb::ZERO);
    let (w4, carry) = w4.mac(q3[3], modulus[1], carry);
    let (w5, carry) = w5.mac(q3[3], modulus[2], carry);
    let (w6, carry) = w6.mac(q3[3], modulus[3], carry);
    let (w7, carry) = w7.mac(q3[3], modulus[4], carry);
    let (w8, _) = w8.mac(q3[3], modulus[5], carry);

    let (w4, carry) = w4.mac(q3[4], modulus[0], Limb::ZERO);
    let (w5, carry) = w5.mac(q3[4], modulus[1], carry);
    let (w6, carry) = w6.mac(q3[4], modulus[2], carry);
    let (w7, carry) = w7.mac(q3[4], modulus[3], carry);
    let (w8, _) = w8.mac(q3[4], modulus[4], carry);

    let (w5, carry) = w5.mac(q3[5], modulus[0], Limb::ZERO);
    let (w6, carry) = w6.mac(q3[5], modulus[1], carry);
    let (w7, carry) = w7.mac(q3[5], modulus[2], carry);
    let (w8, _) = w8.mac(q3[5], modulus[3], carry);

    let (w6, carry) = w6.mac(q3[6], modulus[0], Limb::ZERO);
    let (w7, carry) = w7.mac(q3[6], modulus[1], carry);
    let (w8, _) = w8.mac(q3[6], modulus[2], carry);

    let (w7, carry) = w7.mac(q3[7], modulus[0], Limb::ZERO);
    let (w8, _) = w8.mac(q3[7], modulus[1], carry);

    let (w8, _) = w8.mac(q3[8], modulus[0], Limb::ZERO);

    [w0, w1, w2, w3, w4, w5, w6, w7, w8]
}

#[inline]
#[allow(clippy::too_many_arguments)]
const fn sub_inner_nine(l: [Limb; 9], r: [Limb; 9]) -> [Limb; 9] {
    let (w0, borrow) = l[0].sbb(r[0], Limb::ZERO);
    let (w1, borrow) = l[1].sbb(r[1], borrow);
    let (w2, borrow) = l[2].sbb(r[2], borrow);
    let (w3, borrow) = l[3].sbb(r[3], borrow);
    let (w4, borrow) = l[4].sbb(r[4], borrow);
    let (w5, borrow) = l[5].sbb(r[5], borrow);
    let (w6, borrow) = l[6].sbb(r[6], borrow);
    let (w7, borrow) = l[7].sbb(r[7], borrow);
    let (w8, _borrow) = l[8].sbb(r[8], borrow);

    // If underflow occured in the final limb - don't care (= add b^{k+1}).
    [w0, w1, w2, w3, w4, w5, w6, w7, w8]
}

#[inline]
#[allow(clippy::too_many_arguments)]
const fn subtract_n_if_necessary(r: [Limb; 9]) -> [Limb; 9] {
    let modulus = MODULUS.as_limbs();

    let (w0, borrow) = r[0].sbb(modulus[0], Limb::ZERO);
    let (w1, borrow) = r[1].sbb(modulus[1], borrow);
    let (w2, borrow) = r[2].sbb(modulus[2], borrow);
    let (w3, borrow) = r[3].sbb(modulus[3], borrow);
    let (w4, borrow) = r[4].sbb(modulus[4], borrow);
    let (w5, borrow) = r[5].sbb(modulus[5], borrow);
    let (w6, borrow) = r[6].sbb(modulus[6], borrow);
    let (w7, borrow) = r[7].sbb(modulus[7], borrow);
    let (w8, borrow) = r[8].sbb(Limb::ZERO, borrow);

    // If underflow occurred in the final limb, borrow = 0xfff...fff, otherwise
    // borrow = 0x000...000. Thus, we use it as a mask to conditionally add
    // the modulus.
    let (w0, carry) = w0.adc(modulus[0].bitand(borrow), Limb::ZERO);
    let (w1, carry) = w1.adc(modulus[1].bitand(borrow), carry);
    let (w2, carry) = w2.adc(modulus[2].bitand(borrow), carry);
    let (w3, carry) = w3.adc(modulus[3].bitand(borrow), carry);
    let (w4, carry) = w4.adc(modulus[4].bitand(borrow), carry);
    let (w5, carry) = w5.adc(modulus[5].bitand(borrow), carry);
    let (w6, carry) = w6.adc(modulus[6].bitand(borrow), carry);
    let (w7, carry) = w7.adc(modulus[7].bitand(borrow), carry);
    let (w8, _carry) = w8.adc(Limb::ZERO, carry);

    [w0, w1, w2, w3, w4, w5, w6, w7, w8]
}
