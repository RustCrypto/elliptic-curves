//! Field arithmetic modulo p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1

use crate::ScalarBytes;
use core::convert::TryInto;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "getrandom")]
use getrandom::getrandom;

use super::util::{adc, mac, mac_typemax, sbb};

/// Constant representing the modulus
/// p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
/// p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
pub const MODULUS: FieldElement = FieldElement([
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
]);

/// R = 2^256 mod p
const R: FieldElement = FieldElement([
    0x0000_0001_0000_03d1,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
]);

/// R^2 = 2^512 mod p
const R2: FieldElement = FieldElement([
    0x0000_07a2_000e_90a1,
    0x0000_0000_0000_0001,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
]);

/// INV = -(p^-1 mod 2^64) mod 2^64
const INV: u64 = 0xd838_091d_d225_3531;

/// An element in the finite field modulo p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
// The internal representation is in little-endian order. Elements are always in
// Montgomery form; i.e., FieldElement(a) = aR mod p, with R = 2^256.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(crate) [u64; 4]);

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &FieldElement, b: &FieldElement, choice: Choice) -> FieldElement {
        FieldElement([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        FieldElement::zero()
    }
}

impl FieldElement {
    /// Returns the zero element.
    pub const fn zero() -> FieldElement {
        FieldElement([0, 0, 0, 0])
    }

    /// Returns the multiplicative identity.
    pub const fn one() -> FieldElement {
        R
    }

    /// Returns a uniformly-random element within the field.
    #[cfg(feature = "getrandom")]
    pub fn generate() -> Self {
        // We reduce a random 512-bit value into a 256-bit field, which results in a
        // negligible bias from the uniform distribution.
        let mut buf = [0; 64];
        getrandom(&mut buf).unwrap();
        FieldElement::from_bytes_wide(buf)
    }

    #[cfg(feature = "getrandom")]
    fn from_bytes_wide(bytes: [u8; 64]) -> Self {
        FieldElement::montgomery_reduce(
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
            u64::from_be_bytes(bytes[40..48].try_into().unwrap()),
            u64::from_be_bytes(bytes[48..56].try_into().unwrap()),
            u64::from_be_bytes(bytes[56..64].try_into().unwrap()),
        )
    }

    /// Attempts to parse the given byte array as an SEC-1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        let mut w = [0u64; 4];

        // Interpret the bytes as a big-endian integer w.
        w[3] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        w[2] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        w[1] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        w[0] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());

        // If w is in the range [0, p) then w - p will overflow, resulting in a borrow
        // value of 2^64 - 1.
        let (_, borrow) = sbb(w[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb(w[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb(w[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb(w[3], MODULUS.0[3], borrow);
        let is_some = (borrow as u8) & 1;

        // Convert w to Montgomery form: w * R^2 * R^-1 mod p = wR mod p
        CtOption::new(FieldElement(w).mul(&R2), Choice::from(is_some))
    }

    /// Returns the SEC-1 encoding of this field element.
    pub fn to_bytes(&self) -> [u8; 32] {
        // Convert from Montgomery form to canonical form
        let tmp =
            FieldElement::montgomery_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0);

        let mut ret = [0; 32];
        ret[0..8].copy_from_slice(&tmp.0[3].to_be_bytes());
        ret[8..16].copy_from_slice(&tmp.0[2].to_be_bytes());
        ret[16..24].copy_from_slice(&tmp.0[1].to_be_bytes());
        ret[24..32].copy_from_slice(&tmp.0[0].to_be_bytes());
        ret
    }

    /// Determine if this `FieldElement` is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&FieldElement::zero())
    }

    /// Determine if this `FieldElement` is odd in the SEC-1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        let bytes = self.to_bytes();
        (bytes[31] & 1).into()
    }

    /// Returns self + rhs mod p
    pub const fn add(&self, rhs: &Self) -> Self {
        // Bit 256 of p is set, so addition can result in five words.
        let (w0, carry) = adc(self.0[0], rhs.0[0], 0);
        let (w1, carry) = adc(self.0[1], rhs.0[1], carry);
        let (w2, carry) = adc(self.0[2], rhs.0[2], carry);
        let (w3, w4) = adc(self.0[3], rhs.0[3], carry);

        // Attempt to subtract the modulus, to ensure the result is in the field.
        Self::sub_inner(
            w0,
            w1,
            w2,
            w3,
            w4,
            MODULUS.0[0],
            MODULUS.0[1],
            MODULUS.0[2],
            MODULUS.0[3],
            0,
        )
    }

    /// Returns 2*self.
    pub const fn double(&self) -> Self {
        self.add(self)
    }

    /// Returns self - rhs mod p
    pub const fn subtract(&self, rhs: &Self) -> Self {
        Self::sub_inner(
            self.0[0], self.0[1], self.0[2], self.0[3], 0, rhs.0[0], rhs.0[1], rhs.0[2], rhs.0[3],
            0,
        )
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    const fn sub_inner(
        l0: u64,
        l1: u64,
        l2: u64,
        l3: u64,
        l4: u64,
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
    ) -> Self {
        let (w0, borrow) = sbb(l0, r0, 0);
        let (w1, borrow) = sbb(l1, r1, borrow);
        let (w2, borrow) = sbb(l2, r2, borrow);
        let (w3, borrow) = sbb(l3, r3, borrow);
        let (_, borrow) = sbb(l4, r4, borrow);

        // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the
        // modulus.
        let (w0, carry) = adc(w0, MODULUS.0[0] & borrow, 0);
        let (w1, carry) = adc(w1, MODULUS.0[1] & borrow, carry);
        let (w2, carry) = adc(w2, MODULUS.0[2] & borrow, carry);
        let (w3, _) = adc(w3, MODULUS.0[3] & borrow, carry);

        FieldElement([w0, w1, w2, w3])
    }

    /// Montgomery Multiplication
    ///
    /// For secp256k1, all of the limbs of p (except the first!) are 2^64 -1.
    /// Thus, all multiplications by these limbs can be simplified to a shift
    /// and subtraction:
    /// ```text
    ///     a_i * (2^64 - 1) = a_i * 2^64 - a_i = (a_i << 64) - a_i
    /// ```
    ///
    /// References:
    /// - Handbook of Applied Cryptography, Chapter 14
    ///   Algorithm 14.36
    ///   http://cacr.uwaterloo.ca/hac/about/chap14.pdf
    #[inline]
    #[allow(clippy::too_many_arguments)]
    const fn montgomery_mulmod(
        x0: u64,
        x1: u64,
        x2: u64,
        x3: u64,
        y0: u64,
        y1: u64,
        y2: u64,
        y3: u64,
    ) -> Self {
        let u = ((x0 as u128) * (y0 as u128)).wrapping_mul(INV as u128) as u64;
        let (a0, carry) = mac(0, u, MODULUS.0[0], 0);
        let (a1, carry) = mac_typemax(0, u, carry);
        let (a2, carry) = mac_typemax(0, u, carry);
        let (a3, carry) = mac_typemax(0, u, carry);
        let (a4, carry2) = adc(0, 0, carry);

        let (_, carry) = mac(a0, x0, y0, 0);
        let (a1, carry) = mac(a1, x0, y1, carry);
        let (a2, carry) = mac(a2, x0, y2, carry);
        let (a3, carry) = mac(a3, x0, y3, carry);
        let (a4, a5) = adc(a4, carry2, carry);

        let u = ((a1 as u128) + (x1 as u128) * (y0 as u128)).wrapping_mul(INV as u128) as u64;
        let (a1, carry) = mac(a1, u, MODULUS.0[0], 0);
        let (a2, carry) = mac_typemax(a2, u, carry);
        let (a3, carry) = mac_typemax(a3, u, carry);
        let (a4, carry) = mac_typemax(a4, u, carry);
        let (a5, carry2) = adc(a5, 0, carry);

        let (_, carry) = mac(a1, x1, y0, 0);
        let (a2, carry) = mac(a2, x1, y1, carry);
        let (a3, carry) = mac(a3, x1, y2, carry);
        let (a4, carry) = mac(a4, x1, y3, carry);
        let (a5, a6) = adc(a5, carry2, carry);

        let u = ((a2 as u128) + (x2 as u128) * (y0 as u128)).wrapping_mul(INV as u128) as u64;
        let (a2, carry) = mac(a2, u, MODULUS.0[0], 0);
        let (a3, carry) = mac_typemax(a3, u, carry);
        let (a4, carry) = mac_typemax(a4, u, carry);
        let (a5, carry) = mac_typemax(a5, u, carry);
        let (a6, carry2) = adc(a6, 0, carry);

        let (_, carry) = mac(a2, x2, y0, 0);
        let (a3, carry) = mac(a3, x2, y1, carry);
        let (a4, carry) = mac(a4, x2, y2, carry);
        let (a5, carry) = mac(a5, x2, y3, carry);
        let (a6, a7) = adc(a6, carry2, carry);

        let u = ((a3 as u128) + (x3 as u128) * (y0 as u128)).wrapping_mul(INV as u128) as u64;
        let (a3, carry) = mac(a3, u, MODULUS.0[0], 0);
        let (a4, carry) = mac_typemax(a4, u, carry);
        let (a5, carry) = mac_typemax(a5, u, carry);
        let (a6, carry) = mac_typemax(a6, u, carry);
        let (a7, carry2) = adc(a7, 0, carry);

        let (_, carry) = mac(a3, x3, y0, 0);
        let (a4, carry) = mac(a4, x3, y1, carry);
        let (a5, carry) = mac(a5, x3, y2, carry);
        let (a6, carry) = mac(a6, x3, y3, carry);
        let (a7, a8) = adc(a7, carry2, carry);

        // Result may be within MODULUS of the correct value
        Self::sub_inner(
            a4,
            a5,
            a6,
            a7,
            a8,
            MODULUS.0[0],
            MODULUS.0[1],
            MODULUS.0[2],
            MODULUS.0[3],
            0,
        )
    }

    /// Montgomery Reduction
    ///
    /// For secp256k1, all of the limbs of p (except the first!) are 2^64 -1.
    /// Thus, all multiplications by this limb can be simplified to a shift
    /// and subtraction:
    /// ```text
    ///     a_i * (2^64 - 1) = a_i * 2^64 - a_i = (a_i << 64) - a_i
    /// ```
    ///
    /// References:
    /// - Handbook of Applied Cryptography, Chaper 14
    ///   Algorithm 14.32
    ///   http://cacr.uwaterloo.ca/hac/about/chap14.pdf
    #[inline]
    #[allow(clippy::too_many_arguments)]
    const fn montgomery_reduce(
        t0: u64,
        t1: u64,
        t2: u64,
        t3: u64,
        t4: u64,
        t5: u64,
        t6: u64,
        t7: u64,
    ) -> Self {
        let k = t0.wrapping_mul(INV);
        let (_, carry) = mac(t0, k, MODULUS.0[0], 0);
        let (r1, carry) = mac_typemax(t1, k, carry);
        let (r2, carry) = mac_typemax(t2, k, carry);
        let (r3, carry) = mac_typemax(t3, k, carry);
        let (r4, r5) = adc(t4, 0, carry);

        let k = r1.wrapping_mul(INV);
        let (_, carry) = mac(r1, k, MODULUS.0[0], 0);
        let (r2, carry) = mac_typemax(r2, k, carry);
        let (r3, carry) = mac_typemax(r3, k, carry);
        let (r4, carry) = mac_typemax(r4, k, carry);
        let (r5, r6) = adc(t5, r5, carry);

        let k = r2.wrapping_mul(INV);
        let (_, carry) = mac(r2, k, MODULUS.0[0], 0);
        let (r3, carry) = mac_typemax(r3, k, carry);
        let (r4, carry) = mac_typemax(r4, k, carry);
        let (r5, carry) = mac_typemax(r5, k, carry);
        let (r6, r7) = adc(t6, r6, carry);

        let k = r3.wrapping_mul(INV);
        let (_, carry) = mac(r3, k, MODULUS.0[0], 0);
        let (r4, carry) = mac_typemax(r4, k, carry);
        let (r5, carry) = mac_typemax(r5, k, carry);
        let (r6, carry) = mac_typemax(r6, k, carry);
        let (r7, r8) = adc(t7, r7, carry);

        // Result may be within MODULUS of the correct value
        Self::sub_inner(
            r4,
            r5,
            r6,
            r7,
            r8,
            MODULUS.0[0],
            MODULUS.0[1],
            MODULUS.0[2],
            MODULUS.0[3],
            0,
        )
    }

    /// Returns self * rhs mod p
    pub const fn mul(&self, rhs: &Self) -> Self {
        FieldElement::montgomery_mulmod(
            self.0[0], self.0[1], self.0[2], self.0[3], rhs.0[0], rhs.0[1], rhs.0[2], rhs.0[3],
        )
    }

    /// Returns self * self mod p
    pub const fn square(&self) -> Self {
        // TODO: Implement an efficient squaring algorithm
        // perhaps algorithm 14.16 from the HAC?
        FieldElement::montgomery_mulmod(
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[0], self.0[1], self.0[2], self.0[3],
        )
    }

    /// Returns `self^by`, where `by` is a little-endian integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent.** If the exponent
    /// is fixed, this operation is effectively constant time.
    pub fn pow_vartime(&self, by: &[u64; 4]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();

                if ((*e >> i) & 1) == 1 {
                    res = res * self;
                }
            }
        }
        res
    }

    /// Returns the multiplicative inverse of self, if self is non-zero.
    pub fn invert(&self) -> CtOption<Self> {
        // We need to find b such that b * a ≡ 1 mod p. As we are in a prime
        // field, we can apply Fermat's Little Theorem:
        //
        //    a^p         ≡ a mod p
        //    a^(p-1)     ≡ 1 mod p
        //    a^(p-2) * a ≡ 1 mod p
        //
        // Thus inversion can be implemented with a single exponentiation.
        let inverse = self.pow_vartime(&[
            0xFFFF_FFFE_FFFF_FC2D,
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
        ]);

        CtOption::new(inverse, !self.is_zero())
    }

    /// Returns the square root of self mod p, or `None` if no square root exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // We need to find alpha such that alpha^2 = beta mod p. For secp256k1,
        // p ≡ 3 mod 4. By Euler's Criterion, beta^(p-1)/2 ≡ 1 mod p. So:
        //
        //     alpha^2 = beta beta^((p - 1) / 2) mod p ≡ beta^((p + 1) / 2) mod p
        //     alpha = ± beta^((p + 1) / 4) mod p
        //
        // Thus sqrt can be implemented with a single exponentiation.
        let sqrt = self.pow_vartime(&[
            0xffff_ffff_bfff_ff0c,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x3fff_ffff_ffff_ffff,
        ]);

        CtOption::new(
            sqrt,
            (&sqrt * &sqrt).ct_eq(self), // Only return Some if it's the square root.
        )
    }
}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement::add(self, other)
    }
}

impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement::add(&self, other)
    }
}

impl AddAssign<FieldElement> for FieldElement {
    fn add_assign(&mut self, rhs: FieldElement) {
        *self = FieldElement::add(self, &rhs);
    }
}

impl Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        FieldElement::subtract(self, other)
    }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        FieldElement::subtract(&self, other)
    }
}

impl SubAssign<FieldElement> for FieldElement {
    fn sub_assign(&mut self, rhs: FieldElement) {
        *self = FieldElement::subtract(self, &rhs);
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement::mul(self, other)
    }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement::mul(&self, other)
    }
}

impl MulAssign<FieldElement> for FieldElement {
    fn mul_assign(&mut self, rhs: FieldElement) {
        *self = FieldElement::mul(self, &rhs);
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement::zero() - &self
    }
}

impl<'a> Neg for &'a FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement::zero() - self
    }
}

impl From<FieldElement> for ScalarBytes {
    fn from(fe: FieldElement) -> Self {
        fe.to_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use fiat_crypto::secp256k1_64::{
        fiat_secp256k1_add, fiat_secp256k1_mul, fiat_secp256k1_opp, fiat_secp256k1_square,
        fiat_secp256k1_sub,
    };
    use proptest::{num::u64::ANY, prelude::*};

    use super::FieldElement;
    use crate::arithmetic::test_vectors::field::DBL_TEST_VECTORS;

    #[test]
    fn zero_is_additive_identity() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();
        assert_eq!(zero.add(&zero), zero);
        assert_eq!(one.add(&zero), one);
    }

    #[test]
    fn one_is_multiplicative_identity() {
        let one = FieldElement::one();
        assert_eq!(one.mul(&one), one);
    }

    #[test]
    fn from_bytes() {
        assert_eq!(
            FieldElement::from_bytes([0; 32]).unwrap(),
            FieldElement::zero()
        );
        assert_eq!(
            FieldElement::from_bytes([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ])
            .unwrap(),
            FieldElement::one()
        );
        assert!(bool::from(FieldElement::from_bytes([0xff; 32]).is_none()));
    }

    #[test]
    fn to_bytes() {
        assert_eq!(FieldElement::zero().to_bytes(), [0; 32]);
        assert_eq!(
            FieldElement::one().to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ]
        );
    }

    #[test]
    fn repeated_add() {
        let mut r = FieldElement::one();
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(hex::encode(r.to_bytes()), DBL_TEST_VECTORS[i]);
            r = r + &r;
        }
    }

    #[test]
    fn repeated_double() {
        let mut r = FieldElement::one();
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(hex::encode(r.to_bytes()), DBL_TEST_VECTORS[i]);
            r = r.double();
        }
    }

    #[test]
    fn repeated_mul() {
        let mut r = FieldElement::one();
        let two = r + &r;
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(hex::encode(r.to_bytes()), DBL_TEST_VECTORS[i]);
            r = r * &two;
        }
    }

    #[test]
    fn negation() {
        let two = FieldElement::one().double();
        let neg_two = -two;
        assert_eq!(two + &neg_two, FieldElement::zero());
        assert_eq!(-neg_two, two);
    }

    #[test]
    fn pow_vartime() {
        let one = FieldElement::one();
        let two = one + &one;
        let four = two.square();
        assert_eq!(two.pow_vartime(&[2, 0, 0, 0]), four);
    }

    #[test]
    fn invert() {
        assert!(bool::from(FieldElement::zero().invert().is_none()));

        let one = FieldElement::one();
        assert_eq!(one.invert().unwrap(), one);

        let two = one + &one;
        let inv_two = two.invert().unwrap();
        assert_eq!(two * &inv_two, one);
    }

    #[test]
    fn sqrt() {
        let one = FieldElement::one();
        let two = one + &one;
        let four = two.square();
        assert_eq!(four.sqrt().unwrap(), two);
    }

    proptest! {
        /// This checks behaviour well within the field ranges, because it doesn't set the
        /// highest limb.
        #[test]
        fn add_then_sub(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
            b0 in ANY,
            b1 in ANY,
            b2 in ANY,
        ) {
            let a = FieldElement([a0, a1, a2, 0]);
            let b = FieldElement([b0, b1, b2, 0]);
            assert_eq!(a.add(&b).subtract(&a), b);
        }

        /// These tests fuzz the Field arithmetic implementation against
        /// fiat-crypto.
        #[test]
        fn mul_with_fiat(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
            b0 in ANY,
            b1 in ANY,
            b2 in ANY,
        ) {
            let mut out: [u64; 4] = [0; 4];
            let a = [a0, a1, a2, 0];
            let b = [b0, b1, b2, 0];
            fiat_secp256k1_mul(&mut out, &a, &b);
            assert_eq!(FieldElement(a).mul(&FieldElement(b)).0, out);
        }

        #[test]
        fn square_with_fiat(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
        ) {
            let mut out: [u64; 4] = [0; 4];
            let a = [a0, a1, a2, 0];
            fiat_secp256k1_square(&mut out, &a);
            assert_eq!(FieldElement(a).square().0, out);
        }

        #[test]
        fn add_with_fiat(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
            b0 in ANY,
            b1 in ANY,
            b2 in ANY,
        ) {
            let mut out: [u64; 4] = [0; 4];
            let a = [a0, a1, a2, 0];
            let b = [b0, b1, b2, 0];
            fiat_secp256k1_add(&mut out, &a, &b);
            assert_eq!(FieldElement(a).add(&FieldElement(b)).0, out);
        }

        #[test]
        fn sub_with_fiat(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
            b0 in ANY,
            b1 in ANY,
            b2 in ANY,
        ) {
            let mut out: [u64; 4] = [0; 4];
            let a = [a0, a1, a2, 0];
            let b = [b0, b1, b2, 0];
            fiat_secp256k1_sub(&mut out, &a, &b);
            assert_eq!(FieldElement(a).subtract(&FieldElement(b)).0, out);
        }

        #[test]
        fn negate_with_fiat(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
        ) {
            let mut out: [u64; 4] = [0; 4];
            let a = [a0, a1, a2, 0];
            fiat_secp256k1_opp(&mut out, &a);
            assert_eq!((-FieldElement(a)).0, out);
        }
    }
}
