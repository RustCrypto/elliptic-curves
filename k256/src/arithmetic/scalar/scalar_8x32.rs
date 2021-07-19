//! ProjectiveArithmetic modulo curve base order using 32-bit limbs.
//! Ported from <https://github.com/bitcoin-core/secp256k1>

use crate::{
    arithmetic::util::{adc32, sbb32},
    FieldBytes,
};
use core::convert::TryInto;
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "zeroize")]
use elliptic_curve::zeroize::Zeroize;

/// Constant representing the modulus
/// n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
// TODO(tarcieri): use `Secp256k1::ORDER.into_limbs()`
pub const MODULUS: [u32; 8] = [
    0xD036_4141,
    0xBFD2_5E8C,
    0xAF48_A03B,
    0xBAAE_DCE6,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
];

/// Limbs of 2^256 minus the secp256k1 order.
pub const NEG_MODULUS: [u32; 8] = [
    !MODULUS[0] + 1,
    !MODULUS[1],
    !MODULUS[2],
    !MODULUS[3],
    !MODULUS[4],
    !MODULUS[5],
    !MODULUS[6],
    !MODULUS[7],
];

/// Constant representing the modulus / 2
const FRAC_MODULUS_2: [u32; 8] = [
    0x681B_20A0,
    0xDFE9_2F46,
    0x57A4_501D,
    0x5D57_6E73,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF,
    0x7FFF_FFFF,
];

/// Subtracts a (little-endian) multi-limb number from another multi-limb number,
/// returning the result and the resulting borrow as a sinle-limb value.
/// The borrow can be either `0` or `<u32>::MAX`.
#[inline(always)]
fn sbb_array(lhs: &[u32; 8], rhs: &[u32; 8]) -> ([u32; 8], u32) {
    let borrow = 0;
    let (r0, borrow) = sbb32(lhs[0], rhs[0], borrow);
    let (r1, borrow) = sbb32(lhs[1], rhs[1], borrow);
    let (r2, borrow) = sbb32(lhs[2], rhs[2], borrow);
    let (r3, borrow) = sbb32(lhs[3], rhs[3], borrow);
    let (r4, borrow) = sbb32(lhs[4], rhs[4], borrow);
    let (r5, borrow) = sbb32(lhs[5], rhs[5], borrow);
    let (r6, borrow) = sbb32(lhs[6], rhs[6], borrow);
    let (r7, borrow) = sbb32(lhs[7], rhs[7], borrow);
    ([r0, r1, r2, r3, r4, r5, r6, r7], borrow)
}

/// Subtracts a (little-endian) multi-limb number from another multi-limb number,
/// returning the result and the resulting borrow as a constant-time `Choice`
/// (`0` if there was no borrow and `1` if there was).
#[inline(always)]
fn sbb_array_with_underflow(lhs: &[u32; 8], rhs: &[u32; 8]) -> ([u32; 8], Choice) {
    let (res, borrow) = sbb_array(lhs, rhs);
    (res, Choice::from((borrow >> 31) as u8))
}

/// Adds a (little-endian) multi-limb number to another multi-limb number,
/// returning the result and the resulting carry as a sinle-limb value.
/// The carry can be either `0` or `1`.
#[inline(always)]
fn adc_array(lhs: &[u32; 8], rhs: &[u32; 8]) -> ([u32; 8], u32) {
    let carry = 0;
    let (r0, carry) = adc32(lhs[0], rhs[0], carry);
    let (r1, carry) = adc32(lhs[1], rhs[1], carry);
    let (r2, carry) = adc32(lhs[2], rhs[2], carry);
    let (r3, carry) = adc32(lhs[3], rhs[3], carry);
    let (r4, carry) = adc32(lhs[4], rhs[4], carry);
    let (r5, carry) = adc32(lhs[5], rhs[5], carry);
    let (r6, carry) = adc32(lhs[6], rhs[6], carry);
    let (r7, carry) = adc32(lhs[7], rhs[7], carry);
    ([r0, r1, r2, r3, r4, r5, r6, r7], carry)
}

/// Adds a (little-endian) multi-limb number to another multi-limb number,
/// returning the result and the resulting carry as a constant-time `Choice`
/// (`0` if there was no carry and `1` if there was).
#[inline(always)]
fn adc_array_with_overflow(lhs: &[u32; 8], rhs: &[u32; 8]) -> ([u32; 8], Choice) {
    let (res, carry) = adc_array(lhs, rhs);
    (res, Choice::from(carry as u8))
}

#[inline(always)]
fn conditional_select(a: &[u32; 8], b: &[u32; 8], choice: Choice) -> [u32; 8] {
    [
        u32::conditional_select(&a[0], &b[0], choice),
        u32::conditional_select(&a[1], &b[1], choice),
        u32::conditional_select(&a[2], &b[2], choice),
        u32::conditional_select(&a[3], &b[3], choice),
        u32::conditional_select(&a[4], &b[4], choice),
        u32::conditional_select(&a[5], &b[5], choice),
        u32::conditional_select(&a[6], &b[6], choice),
        u32::conditional_select(&a[7], &b[7], choice),
    ]
}

/// Constant-time comparison.
#[inline(always)]
fn ct_less(a: u32, b: u32) -> u32 {
    // Do not convert to Choice since it is only used internally,
    // and we don't want loss of performance.
    (a < b) as u32
}

/// Add a to the number defined by (c0,c1,c2). c2 must never overflow.
fn sumadd(a: u32, c0: u32, c1: u32, c2: u32) -> (u32, u32, u32) {
    let new_c0 = c0.wrapping_add(a); // overflow is handled on the next line
    let over: u32 = if new_c0 < a { 1 } else { 0 };
    let new_c1 = c1.wrapping_add(over); // overflow is handled on the next line
    let new_c2 = c2 + ct_less(new_c1, over); // never overflows by contract
    (new_c0, new_c1, new_c2)
}

/// Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero.
fn sumadd_fast(a: u32, c0: u32, c1: u32) -> (u32, u32) {
    let new_c0 = c0.wrapping_add(a); // overflow is handled on the next line
    let new_c1 = c1 + ct_less(new_c0, a); // never overflows by contract (verified the next line)
    debug_assert!((new_c1 != 0) | (new_c0 >= a));
    (new_c0, new_c1)
}

/// Add a*b to the number defined by (c0,c1,c2). c2 must never overflow.
fn muladd(a: u32, b: u32, c0: u32, c1: u32, c2: u32) -> (u32, u32, u32) {
    let t = (a as u64) * (b as u64);
    let th = (t >> 32) as u32; // at most 0xFFFFFFFFFFFFFFFE
    let tl = t as u32;

    let new_c0 = c0.wrapping_add(tl); // overflow is handled on the next line
    let new_th = th + ct_less(new_c0, tl); // at most 0xFFFFFFFFFFFFFFFF
    let new_c1 = c1.wrapping_add(new_th); // overflow is handled on the next line
    let new_c2 = c2 + ct_less(new_c1, new_th); // never overflows by contract (verified in the next line)
    debug_assert!((new_c1 >= new_th) || (new_c2 != 0));
    (new_c0, new_c1, new_c2)
}

/// Add a*b to the number defined by (c0,c1). c1 must never overflow.
fn muladd_fast(a: u32, b: u32, c0: u32, c1: u32) -> (u32, u32) {
    let t = (a as u64) * (b as u64);
    let th = (t >> 32) as u32; // at most 0xFFFFFFFFFFFFFFFE
    let tl = t as u32;

    let new_c0 = c0.wrapping_add(tl); // overflow is handled on the next line
    let new_th = th + ct_less(new_c0, tl); // at most 0xFFFFFFFFFFFFFFFF
    let new_c1 = c1 + new_th; // never overflows by contract (verified in the next line)
    debug_assert!(new_c1 >= new_th);
    (new_c0, new_c1)
}

/// A scalar with arithmetic modulo curve order, represented as 8 32-bit limbs (little-endian).
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct Scalar8x32([u32; 8]);

impl Scalar8x32 {
    /// Returns the zero scalar.
    pub const fn zero() -> Self {
        Self([0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Returns the multiplicative identity.
    pub const fn one() -> Self {
        Self([1, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Truncates the scalar to a `u32` value. All the higher bits are discarded.
    pub fn truncate_to_u32(&self) -> u32 {
        self.0[0]
    }

    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        // Interpret the bytes as a big-endian integer w.
        let w7 = ((bytes[0] as u32) << 24)
            | ((bytes[1] as u32) << 16)
            | ((bytes[2] as u32) << 8)
            | (bytes[3] as u32);
        let w6 = ((bytes[4] as u32) << 24)
            | ((bytes[5] as u32) << 16)
            | ((bytes[6] as u32) << 8)
            | (bytes[7] as u32);
        let w5 = ((bytes[8] as u32) << 24)
            | ((bytes[9] as u32) << 16)
            | ((bytes[10] as u32) << 8)
            | (bytes[11] as u32);
        let w4 = ((bytes[12] as u32) << 24)
            | ((bytes[13] as u32) << 16)
            | ((bytes[14] as u32) << 8)
            | (bytes[15] as u32);
        let w3 = ((bytes[16] as u32) << 24)
            | ((bytes[17] as u32) << 16)
            | ((bytes[18] as u32) << 8)
            | (bytes[19] as u32);
        let w2 = ((bytes[20] as u32) << 24)
            | ((bytes[21] as u32) << 16)
            | ((bytes[22] as u32) << 8)
            | (bytes[23] as u32);
        let w1 = ((bytes[24] as u32) << 24)
            | ((bytes[25] as u32) << 16)
            | ((bytes[26] as u32) << 8)
            | (bytes[27] as u32);
        let w0 = ((bytes[28] as u32) << 24)
            | ((bytes[29] as u32) << 16)
            | ((bytes[30] as u32) << 8)
            | (bytes[31] as u32);
        Self([w0, w1, w2, w3, w4, w5, w6, w7])
    }

    /// Attempts to parse the given byte array as an SEC1-encoded scalar.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, modulus).
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        // Interpret the bytes as a big-endian integer w.
        let w7 = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let w6 = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let w5 = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let w4 = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        let w3 = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        let w2 = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        let w1 = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        let w0 = u32::from_be_bytes(bytes[28..32].try_into().unwrap());
        let w = [w0, w1, w2, w3, w4, w5, w6, w7];

        // If w is in the range [0, n) then w - n will underflow
        let (_, underflow) = sbb_array_with_underflow(&w, &MODULUS);
        CtOption::new(Self(w), underflow)
    }

    /// Parses the given byte array as a scalar.
    ///
    /// Subtracts the modulus when the byte array is larger than the modulus.
    pub fn from_bytes_reduced(bytes: &[u8; 32]) -> Self {
        // Interpret the bytes as a big-endian integer w.
        let w7 = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let w6 = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let w5 = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let w4 = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        let w3 = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        let w2 = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        let w1 = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        let w0 = u32::from_be_bytes(bytes[28..32].try_into().unwrap());
        let w = [w0, w1, w2, w3, w4, w5, w6, w7];

        // If w is in the range [0, n) then w - n will underflow
        let (r2, underflow) = sbb_array_with_underflow(&w, &MODULUS);
        Self(conditional_select(&w, &r2, !underflow))
    }

    /// Returns the SEC1 encoding of this scalar.
    pub fn to_bytes(&self) -> FieldBytes {
        let mut ret = FieldBytes::default();
        ret[0..4].copy_from_slice(&self.0[7].to_be_bytes());
        ret[4..8].copy_from_slice(&self.0[6].to_be_bytes());
        ret[8..12].copy_from_slice(&self.0[5].to_be_bytes());
        ret[12..16].copy_from_slice(&self.0[4].to_be_bytes());
        ret[16..20].copy_from_slice(&self.0[3].to_be_bytes());
        ret[20..24].copy_from_slice(&self.0[2].to_be_bytes());
        ret[24..28].copy_from_slice(&self.0[1].to_be_bytes());
        ret[28..32].copy_from_slice(&self.0[0].to_be_bytes());
        ret
    }

    /// Is this scalar greater than or equal to n / 2?
    pub fn is_high(&self) -> Choice {
        let (_, underflow) = sbb_array_with_underflow(&FRAC_MODULUS_2, &self.0);
        underflow
    }

    /// Is this scalar equal to 0?
    pub fn is_zero(&self) -> Choice {
        Choice::from(
            ((self.0[0]
                | self.0[1]
                | self.0[2]
                | self.0[3]
                | self.0[4]
                | self.0[5]
                | self.0[6]
                | self.0[7])
                == 0) as u8,
        )
    }

    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        (self.0[0] as u8 & 1).into()
    }

    /// Negates the scalar.
    pub fn negate(&self) -> Self {
        let (res, _) = sbb_array(&MODULUS, &(self.0));
        Self::conditional_select(&Self(res), &Self::zero(), self.is_zero())
    }

    /// Sums two scalars.
    pub fn add(&self, rhs: &Self) -> Self {
        let (res1, overflow) = adc_array_with_overflow(&(self.0), &(rhs.0));
        let (res2, underflow) = sbb_array_with_underflow(&res1, &MODULUS);
        Self(conditional_select(&res1, &res2, overflow | !underflow))
    }

    /// Subtracts one scalar from the other.
    pub fn sub(&self, rhs: &Self) -> Self {
        let (res1, underflow) = sbb_array_with_underflow(&(self.0), &(rhs.0));
        let (res2, _) = adc_array(&res1, &MODULUS);
        Self(conditional_select(&res1, &res2, underflow))
    }

    /// Multiplies two scalars without modulo reduction, producing up to a 512-bit scalar.
    #[inline(always)] // only used in Scalar::mul(), so won't cause binary bloat
    fn mul_wide(&self, rhs: &Self) -> WideScalar16x32 {
        /* 96 bit accumulator. */
        let c0 = 0;
        let c1 = 0;
        let c2 = 0;

        /* l[0..15] = a[0..7] * b[0..7]. */
        let (c0, c1) = muladd_fast(self.0[0], rhs.0[0], c0, c1);
        let (l0, c0, c1) = (c0, c1, 0);
        let (c0, c1, c2) = muladd(self.0[0], rhs.0[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[1], rhs.0[0], c0, c1, c2);
        let (l1, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[0], rhs.0[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[1], rhs.0[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[2], rhs.0[0], c0, c1, c2);
        let (l2, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[0], rhs.0[3], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[1], rhs.0[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[2], rhs.0[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[3], rhs.0[0], c0, c1, c2);
        let (l3, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[0], rhs.0[4], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[1], rhs.0[3], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[2], rhs.0[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[3], rhs.0[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[4], rhs.0[0], c0, c1, c2);
        let (l4, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[0], rhs.0[5], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[1], rhs.0[4], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[2], rhs.0[3], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[3], rhs.0[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[4], rhs.0[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[5], rhs.0[0], c0, c1, c2);
        let (l5, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[0], rhs.0[6], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[1], rhs.0[5], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[2], rhs.0[4], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[3], rhs.0[3], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[4], rhs.0[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[5], rhs.0[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[6], rhs.0[0], c0, c1, c2);
        let (l6, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[0], rhs.0[7], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[1], rhs.0[6], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[2], rhs.0[5], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[3], rhs.0[4], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[4], rhs.0[3], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[5], rhs.0[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[6], rhs.0[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[7], rhs.0[0], c0, c1, c2);
        let (l7, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[1], rhs.0[7], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[2], rhs.0[6], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[3], rhs.0[5], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[4], rhs.0[4], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[5], rhs.0[3], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[6], rhs.0[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[7], rhs.0[1], c0, c1, c2);
        let (l8, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[2], rhs.0[7], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[3], rhs.0[6], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[4], rhs.0[5], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[5], rhs.0[4], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[6], rhs.0[3], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[7], rhs.0[2], c0, c1, c2);
        let (l9, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[3], rhs.0[7], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[4], rhs.0[6], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[5], rhs.0[5], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[6], rhs.0[4], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[7], rhs.0[3], c0, c1, c2);
        let (l10, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[4], rhs.0[7], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[5], rhs.0[6], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[6], rhs.0[5], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[7], rhs.0[4], c0, c1, c2);
        let (l11, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[5], rhs.0[7], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[6], rhs.0[6], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[7], rhs.0[5], c0, c1, c2);
        let (l12, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[6], rhs.0[7], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[7], rhs.0[6], c0, c1, c2);
        let (l13, c0, c1, _c2) = (c0, c1, c2, 0);
        let (c0, c1) = muladd_fast(self.0[7], rhs.0[7], c0, c1);
        let (l14, c0, c1) = (c0, c1, 0);
        debug_assert!(c1 == 0);
        let l15 = c0;

        WideScalar16x32([
            l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15,
        ])
    }

    /// Multiplies two scalars.
    pub fn mul(&self, rhs: &Self) -> Self {
        let wide_res = self.mul_wide(rhs);
        wide_res.reduce()
    }

    /// Creates a normalized scalar from four given limbs and a possible high (carry) bit
    /// in constant time.
    /// In other words, calculates `(high_bit * 2^256 + limbs) % modulus`.
    fn from_overflow(w: &[u32; 8], high_bit: Choice) -> Self {
        let (r2, underflow) = sbb_array_with_underflow(&w, &MODULUS);
        Self(conditional_select(&w, &r2, !underflow | high_bit))
    }

    /// Right shifts a scalar by given number of bits.
    /// Constant time in the scalar argument, but not in the shift argument.
    pub fn rshift(&self, shift: usize) -> Self {
        let full_shifts = shift >> 5;
        let small_shift = shift & 0x1f;

        let mut res: [u32; 8] = [0u32; 8];

        if shift > 256 {
            return Self(res);
        }

        if small_shift == 0 {
            #[allow(clippy::needless_range_loop)]
            #[allow(clippy::manual_memcpy)]
            for i in 0..(8 - full_shifts) {
                res[i] = self.0[i + full_shifts];
            }
        } else {
            #[allow(clippy::needless_range_loop)]
            for i in 0..(8 - full_shifts) {
                let mut lo = self.0[i + full_shifts] >> small_shift;
                if i < 7 - full_shifts {
                    lo |= self.0[i + full_shifts + 1] << (32 - small_shift);
                }
                res[i] = lo;
            }
        }

        Self(res)
    }

    pub fn conditional_add_bit(&self, bit: usize, flag: Choice) -> Self {
        debug_assert!(bit < 256);

        // Construct Scalar(1 << bit).
        // Since the 255-th bit of the modulus is 1, this will always be within range.
        let bit_lo = bit & 0x1F;
        let w = Self([
            (((bit >> 5) == 0) as u32) << bit_lo,
            (((bit >> 5) == 1) as u32) << bit_lo,
            (((bit >> 5) == 2) as u32) << bit_lo,
            (((bit >> 5) == 3) as u32) << bit_lo,
            (((bit >> 5) == 4) as u32) << bit_lo,
            (((bit >> 5) == 5) as u32) << bit_lo,
            (((bit >> 5) == 6) as u32) << bit_lo,
            (((bit >> 5) == 7) as u32) << bit_lo,
        ]);

        Self::conditional_select(self, &(self.add(&w)), flag)
    }

    pub fn mul_shift_var(&self, b: &Self, shift: usize) -> Self {
        debug_assert!(shift >= 256);

        fn ifelse(c: bool, x: u32, y: u32) -> u32 {
            if c {
                x
            } else {
                y
            }
        }

        let l = self.mul_wide(b);
        let shiftlimbs = shift >> 5;
        let shiftlow = shift & 0x1F;
        let shifthigh = 32 - shiftlow;
        let r0 = ifelse(
            shift < 512,
            (l.0[shiftlimbs] >> shiftlow)
                | ifelse(
                    shift < 480 && shiftlow != 0,
                    l.0[1 + shiftlimbs] << shifthigh,
                    0,
                ),
            0,
        );
        let r1 = ifelse(
            shift < 480,
            (l.0[1 + shiftlimbs] >> shiftlow)
                | ifelse(
                    shift < 448 && shiftlow != 0,
                    l.0[2 + shiftlimbs] << shifthigh,
                    0,
                ),
            0,
        );
        let r2 = ifelse(
            shift < 448,
            (l.0[2 + shiftlimbs] >> shiftlow)
                | ifelse(
                    shift < 416 && shiftlow != 0,
                    l.0[3 + shiftlimbs] << shifthigh,
                    0,
                ),
            0,
        );
        let r3 = ifelse(
            shift < 416,
            (l.0[3 + shiftlimbs] >> shiftlow)
                | ifelse(
                    shift < 384 && shiftlow != 0,
                    l.0[4 + shiftlimbs] << shifthigh,
                    0,
                ),
            0,
        );
        let r4 = ifelse(
            shift < 384,
            (l.0[4 + shiftlimbs] >> shiftlow)
                | ifelse(
                    shift < 352 && shiftlow != 0,
                    l.0[5 + shiftlimbs] << shifthigh,
                    0,
                ),
            0,
        );
        let r5 = ifelse(
            shift < 352,
            (l.0[5 + shiftlimbs] >> shiftlow)
                | ifelse(
                    shift < 320 && shiftlow != 0,
                    l.0[6 + shiftlimbs] << shifthigh,
                    0,
                ),
            0,
        );
        let r6 = ifelse(
            shift < 320,
            (l.0[6 + shiftlimbs] >> shiftlow)
                | ifelse(
                    shift < 288 && shiftlow != 0,
                    l.0[7 + shiftlimbs] << shifthigh,
                    0,
                ),
            0,
        );
        let r7 = ifelse(shift < 288, l.0[7 + shiftlimbs] >> shiftlow, 0);

        let res = Self([r0, r1, r2, r3, r4, r5, r6, r7]);

        // Check the highmost discarded bit and round up if it is set.
        let c = (l.0[(shift - 1) >> 5] >> ((shift - 1) & 0x1f)) & 1;
        res.conditional_add_bit(0, Choice::from(c as u8))
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Scalar8x32 {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize()
    }
}

impl From<u32> for Scalar8x32 {
    fn from(k: u32) -> Self {
        Self([k, 0, 0, 0, 0, 0, 0, 0])
    }
}

impl From<u64> for Scalar8x32 {
    fn from(k: u64) -> Self {
        Self([(k & 0xFFFF) as u32, (k >> 32) as u32, 0, 0, 0, 0, 0, 0])
    }
}

impl ConditionallySelectable for Scalar8x32 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar8x32(conditional_select(&(a.0), &(b.0), choice))
    }
}

impl ConstantTimeEq for Scalar8x32 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
            & self.0[4].ct_eq(&other.0[4])
            & self.0[5].ct_eq(&other.0[5])
            & self.0[6].ct_eq(&other.0[6])
            & self.0[7].ct_eq(&other.0[7])
    }
}

#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
impl From<Scalar8x32> for crate::ScalarBits {
    fn from(scalar: Scalar8x32) -> crate::ScalarBits {
        scalar.0.into()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WideScalar16x32([u32; 16]);

impl WideScalar16x32 {
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut w = [0u32; 16];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(
                bytes[((15 - i) * 4)..((15 - i) * 4 + 4)]
                    .try_into()
                    .unwrap(),
            );
        }
        Self(w)
    }

    #[inline(always)] // only used in Scalar::mul(), so won't cause binary bloat
    pub fn reduce(&self) -> Scalar8x32 {
        let n0 = self.0[8];
        let n1 = self.0[9];
        let n2 = self.0[10];
        let n3 = self.0[11];
        let n4 = self.0[12];
        let n5 = self.0[13];
        let n6 = self.0[14];
        let n7 = self.0[15];

        /* 96 bit accumulator. */

        /* Reduce 512 bits into 385. */
        /* m[0..12] = l[0..7] + n[0..7] * NEG_MODULUS. */
        let c0 = self.0[0];
        let c1 = 0;
        let c2 = 0;
        let (c0, c1) = muladd_fast(n0, NEG_MODULUS[0], c0, c1);
        let (m0, c0, c1) = (c0, c1, 0);
        let (c0, c1) = sumadd_fast(self.0[1], c0, c1);
        let (c0, c1, c2) = muladd(n1, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(n0, NEG_MODULUS[1], c0, c1, c2);
        let (m1, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(self.0[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(n2, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(n1, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(n0, NEG_MODULUS[2], c0, c1, c2);
        let (m2, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(self.0[3], c0, c1, c2);
        let (c0, c1, c2) = muladd(n3, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(n2, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(n1, NEG_MODULUS[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(n0, NEG_MODULUS[3], c0, c1, c2);
        let (m3, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(self.0[4], c0, c1, c2);
        let (c0, c1, c2) = muladd(n4, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(n3, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(n2, NEG_MODULUS[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(n1, NEG_MODULUS[3], c0, c1, c2);
        let (c0, c1, c2) = sumadd(n0, c0, c1, c2);
        let (m4, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(self.0[5], c0, c1, c2);
        let (c0, c1, c2) = muladd(n5, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(n4, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(n3, NEG_MODULUS[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(n2, NEG_MODULUS[3], c0, c1, c2);
        let (c0, c1, c2) = sumadd(n1, c0, c1, c2);
        let (m5, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(self.0[6], c0, c1, c2);
        let (c0, c1, c2) = muladd(n6, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(n5, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(n4, NEG_MODULUS[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(n3, NEG_MODULUS[3], c0, c1, c2);
        let (c0, c1, c2) = sumadd(n2, c0, c1, c2);
        let (m6, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(self.0[7], c0, c1, c2);
        let (c0, c1, c2) = muladd(n7, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(n6, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(n5, NEG_MODULUS[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(n4, NEG_MODULUS[3], c0, c1, c2);
        let (c0, c1, c2) = sumadd(n3, c0, c1, c2);
        let (m7, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(n7, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(n6, NEG_MODULUS[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(n5, NEG_MODULUS[3], c0, c1, c2);
        let (c0, c1, c2) = sumadd(n4, c0, c1, c2);
        let (m8, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(n7, NEG_MODULUS[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(n6, NEG_MODULUS[3], c0, c1, c2);
        let (c0, c1, c2) = sumadd(n5, c0, c1, c2);
        let (m9, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(n7, NEG_MODULUS[3], c0, c1, c2);
        let (c0, c1, c2) = sumadd(n6, c0, c1, c2);
        let (m10, c0, c1, _c2) = (c0, c1, c2, 0);
        let (c0, c1) = sumadd_fast(n7, c0, c1);
        let (m11, c0, _c1) = (c0, c1, 0);
        debug_assert!(c0 <= 1);
        let m12 = c0;

        /* Reduce 385 bits into 258. */
        /* p[0..8] = m[0..7] + m[8..12] * NEG_MODULUS. */
        let c0 = m0;
        let c1 = 0;
        let c2 = 0;
        let (c0, c1) = muladd_fast(m8, NEG_MODULUS[0], c0, c1);
        let (p0, c0, c1) = (c0, c1, 0);
        let (c0, c1) = sumadd_fast(m1, c0, c1);
        let (c0, c1, c2) = muladd(m9, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(m8, NEG_MODULUS[1], c0, c1, c2);
        let (p1, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(m2, c0, c1, c2);
        let (c0, c1, c2) = muladd(m10, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(m9, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(m8, NEG_MODULUS[2], c0, c1, c2);
        let (p2, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(m3, c0, c1, c2);
        let (c0, c1, c2) = muladd(m11, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(m10, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(m9, NEG_MODULUS[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(m8, NEG_MODULUS[3], c0, c1, c2);
        let (p3, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(m4, c0, c1, c2);
        let (c0, c1, c2) = muladd(m12, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(m11, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(m10, NEG_MODULUS[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(m9, NEG_MODULUS[3], c0, c1, c2);
        let (c0, c1, c2) = sumadd(m8, c0, c1, c2);
        let (p4, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(m5, c0, c1, c2);
        let (c0, c1, c2) = muladd(m12, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = muladd(m11, NEG_MODULUS[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(m10, NEG_MODULUS[3], c0, c1, c2);
        let (c0, c1, c2) = sumadd(m9, c0, c1, c2);
        let (p5, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(m6, c0, c1, c2);
        let (c0, c1, c2) = muladd(m12, NEG_MODULUS[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(m11, NEG_MODULUS[3], c0, c1, c2);
        let (c0, c1, c2) = sumadd(m10, c0, c1, c2);
        let (p6, c0, c1, _c2) = (c0, c1, c2, 0);
        let (c0, c1) = sumadd_fast(m7, c0, c1);
        let (c0, c1) = muladd_fast(m12, NEG_MODULUS[3], c0, c1);
        let (c0, c1) = sumadd_fast(m11, c0, c1);
        let (p7, c0, _c1) = (c0, c1, 0);
        let p8 = c0 + m12;
        debug_assert!(p8 <= 2);

        /* Reduce 258 bits into 256. */
        /* r[0..7] = p[0..7] + p[8] * NEG_MODULUS. */
        let mut c = p0 as u64 + (NEG_MODULUS[0] as u64) * (p8 as u64);
        let r0 = (c & 0xFFFFFFFFu64) as u32;
        c >>= 32;
        c += p1 as u64 + (NEG_MODULUS[1] as u64) * (p8 as u64);
        let r1 = (c & 0xFFFFFFFFu64) as u32;
        c >>= 32;
        c += p2 as u64 + (NEG_MODULUS[2] as u64) * (p8 as u64);
        let r2 = (c & 0xFFFFFFFFu64) as u32;
        c >>= 32;
        c += p3 as u64 + (NEG_MODULUS[3] as u64) * (p8 as u64);
        let r3 = (c & 0xFFFFFFFFu64) as u32;
        c >>= 32;
        c += p4 as u64 + p8 as u64;
        let r4 = (c & 0xFFFFFFFFu64) as u32;
        c >>= 32;
        c += p5 as u64;
        let r5 = (c & 0xFFFFFFFFu64) as u32;
        c >>= 32;
        c += p6 as u64;
        let r6 = (c & 0xFFFFFFFFu64) as u32;
        c >>= 32;
        c += p7 as u64;
        let r7 = (c & 0xFFFFFFFFu64) as u32;
        c >>= 32;

        /* Final reduction of r. */
        let high_bit = Choice::from(c as u8);
        Scalar8x32::from_overflow(&[r0, r1, r2, r3, r4, r5, r6, r7], high_bit)
    }
}
