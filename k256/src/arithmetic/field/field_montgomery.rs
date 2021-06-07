//! Field arithmetic modulo p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1

use crate::{
    arithmetic::util::{adc64, mac64, mac64_typemax, sbb64},
    FieldBytes,
};
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "zeroize")]
use elliptic_curve::zeroize::Zeroize;

const fn bytes_to_u64(b: &[u8; 8]) -> u64 {
    ((b[0] as u64) << 56)
        | ((b[1] as u64) << 48)
        | ((b[2] as u64) << 40)
        | ((b[3] as u64) << 32)
        | ((b[4] as u64) << 24)
        | ((b[5] as u64) << 16)
        | ((b[6] as u64) << 8)
        | (b[7] as u64)
}

const fn bytes_to_words(b: &[u8; 32]) -> [u64; 4] {
    let w3 = bytes_to_u64(&[b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let w2 = bytes_to_u64(&[b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    let w1 = bytes_to_u64(&[b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]);
    let w0 = bytes_to_u64(&[b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]);
    [w0, w1, w2, w3]
}

/// Constant representing the modulus
/// p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
/// p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
const MODULUS: FieldElementMontgomery = FieldElementMontgomery([
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
]);

/// R = 2^256 mod p
const R: FieldElementMontgomery = FieldElementMontgomery([
    0x0000_0001_0000_03d1,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
]);

/// R^2 = 2^512 mod p
const R2: FieldElementMontgomery = FieldElementMontgomery([
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
pub struct FieldElementMontgomery(pub(crate) [u64; 4]);

impl FieldElementMontgomery {
    /// Returns the zero element.
    pub const fn zero() -> Self {
        Self([0, 0, 0, 0])
    }

    /// Returns the multiplicative identity.
    pub const fn one() -> Self {
        R
    }

    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        Self(bytes_to_words(bytes)).mul(&R2)
    }

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: &FieldBytes) -> CtOption<Self> {
        let words = bytes_to_words(bytes.as_ref());

        // If w is in the range [0, p) then w - p will overflow, resulting in a borrow
        // value of 2^64 - 1.
        let (_, borrow) = sbb64(words[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb64(words[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb64(words[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb64(words[3], MODULUS.0[3], borrow);
        let is_some = (borrow as u8) & 1;

        // Convert w to Montgomery form: w * R^2 * R^-1 mod p = wR mod p
        CtOption::new(Self(words).mul(&R2), Choice::from(is_some))
    }

    /// Returns the SEC1 encoding of this field element.
    pub fn to_bytes(&self) -> FieldBytes {
        let res = Self::montgomery_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0);
        let mut ret = FieldBytes::default();
        ret[0..8].copy_from_slice(&res.0[3].to_be_bytes());
        ret[8..16].copy_from_slice(&res.0[2].to_be_bytes());
        ret[16..24].copy_from_slice(&res.0[1].to_be_bytes());
        ret[24..32].copy_from_slice(&res.0[0].to_be_bytes());
        ret
    }

    /// Determine if this `FieldElement` is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::zero())
    }

    pub fn normalizes_to_zero(&self) -> Choice {
        self.is_zero()
    }

    /// Determine if this `FieldElement` is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        let bytes = self.to_bytes();
        (bytes[31] & 1).into()
    }

    pub fn normalize_weak(&self) -> Self {
        *self
    }

    pub fn normalize(&self) -> Self {
        *self
    }

    /// Returns self + rhs mod p
    pub const fn add(&self, rhs: &Self) -> Self {
        // Bit 256 of p is set, so addition can result in five words.
        let (w0, carry) = adc64(self.0[0], rhs.0[0], 0);
        let (w1, carry) = adc64(self.0[1], rhs.0[1], carry);
        let (w2, carry) = adc64(self.0[2], rhs.0[2], carry);
        let (w3, w4) = adc64(self.0[3], rhs.0[3], carry);

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

    /// Returns self - rhs mod p
    pub const fn subtract(&self, rhs: &Self) -> Self {
        Self::sub_inner(
            self.0[0], self.0[1], self.0[2], self.0[3], 0, rhs.0[0], rhs.0[1], rhs.0[2], rhs.0[3],
            0,
        )
    }

    pub fn negate(&self, _magnitude: u32) -> Self {
        Self::zero().subtract(self)
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
        let (w0, borrow) = sbb64(l0, r0, 0);
        let (w1, borrow) = sbb64(l1, r1, borrow);
        let (w2, borrow) = sbb64(l2, r2, borrow);
        let (w3, borrow) = sbb64(l3, r3, borrow);
        let (_, borrow) = sbb64(l4, r4, borrow);

        // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the
        // modulus.
        let (w0, carry) = adc64(w0, MODULUS.0[0] & borrow, 0);
        let (w1, carry) = adc64(w1, MODULUS.0[1] & borrow, carry);
        let (w2, carry) = adc64(w2, MODULUS.0[2] & borrow, carry);
        let (w3, _) = adc64(w3, MODULUS.0[3] & borrow, carry);

        Self([w0, w1, w2, w3])
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
        let (a0, carry) = mac64(0, u, MODULUS.0[0], 0);
        let (a1, carry) = mac64_typemax(0, u, carry);
        let (a2, carry) = mac64_typemax(0, u, carry);
        let (a3, carry) = mac64_typemax(0, u, carry);
        let (a4, carry2) = adc64(0, 0, carry);

        let (_, carry) = mac64(a0, x0, y0, 0);
        let (a1, carry) = mac64(a1, x0, y1, carry);
        let (a2, carry) = mac64(a2, x0, y2, carry);
        let (a3, carry) = mac64(a3, x0, y3, carry);
        let (a4, a5) = adc64(a4, carry2, carry);

        let u = ((a1 as u128) + (x1 as u128) * (y0 as u128)).wrapping_mul(INV as u128) as u64;
        let (a1, carry) = mac64(a1, u, MODULUS.0[0], 0);
        let (a2, carry) = mac64_typemax(a2, u, carry);
        let (a3, carry) = mac64_typemax(a3, u, carry);
        let (a4, carry) = mac64_typemax(a4, u, carry);
        let (a5, carry2) = adc64(a5, 0, carry);

        let (_, carry) = mac64(a1, x1, y0, 0);
        let (a2, carry) = mac64(a2, x1, y1, carry);
        let (a3, carry) = mac64(a3, x1, y2, carry);
        let (a4, carry) = mac64(a4, x1, y3, carry);
        let (a5, a6) = adc64(a5, carry2, carry);

        let u = ((a2 as u128) + (x2 as u128) * (y0 as u128)).wrapping_mul(INV as u128) as u64;
        let (a2, carry) = mac64(a2, u, MODULUS.0[0], 0);
        let (a3, carry) = mac64_typemax(a3, u, carry);
        let (a4, carry) = mac64_typemax(a4, u, carry);
        let (a5, carry) = mac64_typemax(a5, u, carry);
        let (a6, carry2) = adc64(a6, 0, carry);

        let (_, carry) = mac64(a2, x2, y0, 0);
        let (a3, carry) = mac64(a3, x2, y1, carry);
        let (a4, carry) = mac64(a4, x2, y2, carry);
        let (a5, carry) = mac64(a5, x2, y3, carry);
        let (a6, a7) = adc64(a6, carry2, carry);

        let u = ((a3 as u128) + (x3 as u128) * (y0 as u128)).wrapping_mul(INV as u128) as u64;
        let (a3, carry) = mac64(a3, u, MODULUS.0[0], 0);
        let (a4, carry) = mac64_typemax(a4, u, carry);
        let (a5, carry) = mac64_typemax(a5, u, carry);
        let (a6, carry) = mac64_typemax(a6, u, carry);
        let (a7, carry2) = adc64(a7, 0, carry);

        let (_, carry) = mac64(a3, x3, y0, 0);
        let (a4, carry) = mac64(a4, x3, y1, carry);
        let (a5, carry) = mac64(a5, x3, y2, carry);
        let (a6, carry) = mac64(a6, x3, y3, carry);
        let (a7, a8) = adc64(a7, carry2, carry);

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
        let (_, carry) = mac64(t0, k, MODULUS.0[0], 0);
        let (r1, carry) = mac64_typemax(t1, k, carry);
        let (r2, carry) = mac64_typemax(t2, k, carry);
        let (r3, carry) = mac64_typemax(t3, k, carry);
        let (r4, r5) = adc64(t4, 0, carry);

        let k = r1.wrapping_mul(INV);
        let (_, carry) = mac64(r1, k, MODULUS.0[0], 0);
        let (r2, carry) = mac64_typemax(r2, k, carry);
        let (r3, carry) = mac64_typemax(r3, k, carry);
        let (r4, carry) = mac64_typemax(r4, k, carry);
        let (r5, r6) = adc64(t5, r5, carry);

        let k = r2.wrapping_mul(INV);
        let (_, carry) = mac64(r2, k, MODULUS.0[0], 0);
        let (r3, carry) = mac64_typemax(r3, k, carry);
        let (r4, carry) = mac64_typemax(r4, k, carry);
        let (r5, carry) = mac64_typemax(r5, k, carry);
        let (r6, r7) = adc64(t6, r6, carry);

        let k = r3.wrapping_mul(INV);
        let (_, carry) = mac64(r3, k, MODULUS.0[0], 0);
        let (r4, carry) = mac64_typemax(r4, k, carry);
        let (r5, carry) = mac64_typemax(r5, k, carry);
        let (r6, carry) = mac64_typemax(r6, k, carry);
        let (r7, r8) = adc64(t7, r7, carry);

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
        Self::montgomery_mulmod(
            self.0[0], self.0[1], self.0[2], self.0[3], rhs.0[0], rhs.0[1], rhs.0[2], rhs.0[3],
        )
    }

    pub fn mul_single(&self, rhs: u32) -> Self {
        self.mul(&Self([rhs as u64, 0, 0, 0]).mul(&R2))
    }

    /// Returns self * self mod p
    pub const fn square(&self) -> Self {
        // TODO: Implement an efficient squaring algorithm
        // perhaps algorithm 14.16 from the HAC?
        Self::montgomery_mulmod(
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[0], self.0[1], self.0[2], self.0[3],
        )
    }
}

impl ConditionallySelectable for FieldElementMontgomery {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

impl ConstantTimeEq for FieldElementMontgomery {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl PartialEq for FieldElementMontgomery {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Default for FieldElementMontgomery {
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElementMontgomery {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
