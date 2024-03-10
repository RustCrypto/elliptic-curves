//! 32-bit secp256r1 field element algorithms.

use super::MODULUS;
use elliptic_curve::bigint::{Limb, U256, U512};

pub(super) const fn add(a: U256, b: U256) -> U256 {
    let a = a.as_limbs();
    let b = b.as_limbs();

    // Bit 256 of p is set, so addition can result in nine words.
    // let (w0, carry) = adc(a[0], b[0], 0);
    let (w0, carry) = a[0].adc(b[0], Limb::ZERO);
    let (w1, carry) = a[1].adc(b[1], carry);
    let (w2, carry) = a[2].adc(b[2], carry);
    let (w3, carry) = a[3].adc(b[3], carry);
    let (w4, carry) = a[4].adc(b[4], carry);
    let (w5, carry) = a[5].adc(b[5], carry);
    let (w6, carry) = a[6].adc(b[6], carry);
    let (w7, w8) = a[7].adc(b[7], carry);
    // Attempt to subtract the modulus, to ensure the result is in the field.
    let modulus = MODULUS.0.as_limbs();

    let (result, _) = sub_inner(
        [w0, w1, w2, w3, w4, w5, w6, w7, w8],
        [
            modulus[0],
            modulus[1],
            modulus[2],
            modulus[3],
            modulus[4],
            modulus[5],
            modulus[6],
            modulus[7],
            Limb::ZERO,
        ],
    );
    U256::new([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ])
}

pub(super) const fn sub(a: U256, b: U256) -> U256 {
    let a = a.as_limbs();
    let b = b.as_limbs();

    let (result, _) = sub_inner(
        [a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], Limb::ZERO],
        [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], Limb::ZERO],
    );
    U256::new([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ])
}

#[inline]
pub(super) const fn to_canonical(a: U256) -> U256 {
    montgomery_reduce(a, U256::ZERO)
}

pub(super) fn from_bytes_wide(a: U512) -> U256 {
    let words = a.to_limbs();
    montgomery_reduce(
        U256::new([
            words[8], words[9], words[10], words[11], words[12], words[13], words[14], words[15],
        ]),
        U256::new([
            words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7],
        ]),
    )
}

/// Montgomery Reduction
///
/// The general algorithm is:
/// ```text
/// A <- input (2n b-limbs)
/// for i in 0..n {
///     k <- A[i] p' mod b
///     A <- A + k p b^i
/// }
/// A <- A / b^n
/// if A >= p {
///     A <- A - p
/// }
/// ```
///
/// For secp256r1, with a 32-bit arithmetic, we have the following
/// simplifications:
///
/// - `p'` is 1, so our multiplicand is simply the first limb of the intermediate A.
///
/// - The first limb of p is 2^32 - 1; multiplications by this limb can be simplified
///   to a shift and subtraction:
///   ```text
///       a_i * (2^32 - 1) = a_i * 2^32 - a_i = (a_i << 32) - a_i
///   ```
///   However, because `p' = 1`, the first limb of p is multiplied by limb i of the
///   intermediate A and then immediately added to that same limb, so we simply
///   initialize the carry to limb i of the intermediate.
///
///   The same applies for the second and third limb.
///
/// - The fourth limb of p is zero, so we can ignore any multiplications by it and just
///   add the carry.
///
///   The same applies for the fifth and sixth limb.
///
/// - The seventh limb of p is one, so we can substitute a `mac` operation with a `adc` one.
///
/// References:
/// - Handbook of Applied Cryptography, Chapter 14
///   Algorithm 14.32
///   http://cacr.uwaterloo.ca/hac/about/chap14.pdf
///
/// - Efficient and Secure Elliptic Curve Cryptography Implementation of Curve P-256
///   Algorithm 7) Montgomery Word-by-Word Reduction
///   https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session6-adalier-mehmet.pdf
#[inline]
#[allow(clippy::too_many_arguments)]
pub(super) const fn montgomery_reduce(lo: U256, hi: U256) -> U256 {
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

    let modulus = MODULUS.0.as_limbs();

    /*
     * let (a0, c) = (0, a0);
     * let (a1, c) = (a1, a0);
     * let (a2, c) = (a2, a0);
     */
    let (a3, carry) = a3.adc(Limb::ZERO, a0);
    let (a4, carry) = a4.adc(Limb::ZERO, carry);
    let (a5, carry) = a5.adc(Limb::ZERO, carry);
    let (a6, carry) = a6.adc(a0, carry);
    // NOTE `modulus[7]` is 2^32 - 1, this could be optimized to `adc` and `sbb`
    // but multiplication costs 1 clock-cycle on several architectures,
    // thanks to parallelization
    let (a7, carry) = a7.mac(a0, modulus[7], carry);
    /* optimization with only adc and sbb
     * let (x, _) = sbb(0, a0, 0);
     * let (y, _) = sbb(a0, 0, (a0 != 0) as u32);
     *
     * (a7, carry) = adc(a7, x, carry);
     * (carry, _) = adc(y, 0, carry);
     */
    let (a8, carry2) = a8.adc(Limb::ZERO, carry);

    let (a4, carry) = a4.adc(Limb::ZERO, a1);
    let (a5, carry) = a5.adc(Limb::ZERO, carry);
    let (a6, carry) = a6.adc(Limb::ZERO, carry);
    let (a7, carry) = a7.adc(a1, carry);
    let (a8, carry) = a8.mac(a1, modulus[7], carry);
    let (a9, carry2) = a9.adc(carry2, carry);

    let (a5, carry) = a5.adc(Limb::ZERO, a2);
    let (a6, carry) = a6.adc(Limb::ZERO, carry);
    let (a7, carry) = a7.adc(Limb::ZERO, carry);
    let (a8, carry) = a8.adc(a2, carry);
    let (a9, carry) = a9.mac(a2, modulus[7], carry);
    let (a10, carry2) = a10.adc(carry2, carry);

    let (a6, carry) = a6.adc(Limb::ZERO, a3);
    let (a7, carry) = a7.adc(Limb::ZERO, carry);
    let (a8, carry) = a8.adc(Limb::ZERO, carry);
    let (a9, carry) = a9.adc(a3, carry);
    let (a10, carry) = a10.mac(a3, modulus[7], carry);
    let (a11, carry2) = a11.adc(carry2, carry);

    let (a7, carry) = a7.adc(Limb::ZERO, a4);
    let (a8, carry) = a8.adc(Limb::ZERO, carry);
    let (a9, carry) = a9.adc(Limb::ZERO, carry);
    let (a10, carry) = a10.adc(a4, carry);
    let (a11, carry) = a11.mac(a4, modulus[7], carry);
    let (a12, carry2) = a12.adc(carry2, carry);

    let (a8, carry) = a8.adc(Limb::ZERO, a5);
    let (a9, carry) = a9.adc(Limb::ZERO, carry);
    let (a10, carry) = a10.adc(Limb::ZERO, carry);
    let (a11, carry) = a11.adc(a5, carry);
    let (a12, carry) = a12.mac(a5, modulus[7], carry);
    let (a13, carry2) = a13.adc(carry2, carry);

    let (a9, carry) = a9.adc(Limb::ZERO, a6);
    let (a10, carry) = a10.adc(Limb::ZERO, carry);
    let (a11, carry) = a11.adc(Limb::ZERO, carry);
    let (a12, carry) = a12.adc(a6, carry);
    let (a13, carry) = a13.mac(a6, modulus[7], carry);
    let (a14, carry2) = a14.adc(carry2, carry);

    let (a10, carry) = a10.adc(Limb::ZERO, a7);
    let (a11, carry) = a11.adc(Limb::ZERO, carry);
    let (a12, carry) = a12.adc(Limb::ZERO, carry);
    let (a13, carry) = a13.adc(a7, carry);
    let (a14, carry) = a14.mac(a7, modulus[7], carry);
    let (a15, a16) = a15.adc(carry2, carry);

    // Result may be within MODULUS of the correct value
    let (result, _) = sub_inner(
        [a8, a9, a10, a11, a12, a13, a14, a15, a16],
        [
            modulus[0],
            modulus[1],
            modulus[2],
            modulus[3],
            modulus[4],
            modulus[5],
            modulus[6],
            modulus[7],
            Limb::ZERO,
        ],
    );

    U256::new([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ])
}

#[inline]
#[allow(clippy::too_many_arguments)]
const fn sub_inner(l: [Limb; 9], r: [Limb; 9]) -> ([Limb; 8], Limb) {
    let (w0, borrow) = l[0].sbb(r[0], Limb::ZERO);
    let (w1, borrow) = l[1].sbb(r[1], borrow);
    let (w2, borrow) = l[2].sbb(r[2], borrow);
    let (w3, borrow) = l[3].sbb(r[3], borrow);
    let (w4, borrow) = l[4].sbb(r[4], borrow);
    let (w5, borrow) = l[5].sbb(r[5], borrow);
    let (w6, borrow) = l[6].sbb(r[6], borrow);
    let (w7, borrow) = l[7].sbb(r[7], borrow);
    let (_, borrow) = l[8].sbb(r[8], borrow);

    // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
    // borrow = 0x000...000. Thus, we use it as a mask to conditionally add
    // the modulus.

    let modulus = MODULUS.0.as_limbs();

    let (w0, carry) = w0.adc(modulus[0].bitand(borrow), Limb::ZERO);
    let (w1, carry) = w1.adc(modulus[1].bitand(borrow), carry);
    let (w2, carry) = w2.adc(modulus[2].bitand(borrow), carry);
    let (w3, carry) = w3.adc(modulus[3].bitand(borrow), carry);
    let (w4, carry) = w4.adc(modulus[4].bitand(borrow), carry);
    let (w5, carry) = w5.adc(modulus[5].bitand(borrow), carry);
    let (w6, carry) = w6.adc(modulus[6].bitand(borrow), carry);
    let (w7, _) = w7.adc(modulus[7].bitand(borrow), carry);

    ([w0, w1, w2, w3, w4, w5, w6, w7], borrow)
}
