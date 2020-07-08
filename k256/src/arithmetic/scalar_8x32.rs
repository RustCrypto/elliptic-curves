use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(test)]
use super::util::{biguint_to_u32_array, u32_array_to_biguint};
#[cfg(test)]
use num_bigint::{BigUint, ToBigUint};

use crate::arithmetic::util::sbb32;

use core::{convert::TryInto};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Constant representing the modulus
/// n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
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

/* Limbs of 2^256 minus the secp256k1 order. */
pub const NEG_MODULUS: [u32; 8] = [
    !MODULUS[0] + 1,
    !MODULUS[1],
    !MODULUS[2],
    !MODULUS[3],
    1,
    0,
    0,
    0,
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

    pub fn truncate_to_u32(&self) -> u32 {
        self.0[0]
    }

    /// Attempts to parse the given byte array as an SEC-1-encoded scalar.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        let mut w = [0u32; 8];

        // Interpret the bytes as a big-endian integer w.
        w[7] = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        w[6] = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        w[5] = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        w[4] = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        w[3] = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        w[2] = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        w[1] = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        w[0] = u32::from_be_bytes(bytes[28..32].try_into().unwrap());

        Self::from_words(w)
    }

    pub fn from_words(w: [u32; 8]) -> CtOption<Self> {
        // If w is in the range [0, n) then w - n will overflow, resulting in a borrow
        // value of 2^64 - 1.
        let (_, borrow) = sbb32(w[0], MODULUS[0], 0);
        let (_, borrow) = sbb32(w[1], MODULUS[1], borrow);
        let (_, borrow) = sbb32(w[2], MODULUS[2], borrow);
        let (_, borrow) = sbb32(w[3], MODULUS[3], borrow);
        let (_, borrow) = sbb32(w[4], MODULUS[4], borrow);
        let (_, borrow) = sbb32(w[5], MODULUS[5], borrow);
        let (_, borrow) = sbb32(w[6], MODULUS[6], borrow);
        let (_, borrow) = sbb32(w[7], MODULUS[7], borrow);
        let is_some = (borrow as u8) & 1;

        CtOption::new(Self(w), Choice::from(is_some))
    }

    /// Returns the SEC-1 encoding of this scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut ret = [0; 32];
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
        let (_, borrow) = sbb32(self.0[0], FRAC_MODULUS_2[0], 0);
        let (_, borrow) = sbb32(self.0[1], FRAC_MODULUS_2[1], borrow);
        let (_, borrow) = sbb32(self.0[2], FRAC_MODULUS_2[2], borrow);
        let (_, borrow) = sbb32(self.0[3], FRAC_MODULUS_2[3], borrow);
        let (_, borrow) = sbb32(self.0[4], FRAC_MODULUS_2[4], borrow);
        let (_, borrow) = sbb32(self.0[5], FRAC_MODULUS_2[5], borrow);
        let (_, borrow) = sbb32(self.0[6], FRAC_MODULUS_2[6], borrow);
        let (_, borrow) = sbb32(self.0[7], FRAC_MODULUS_2[7], borrow);
        (borrow & 1).ct_eq(&0)
    }

    // FIXME: use subtle
    pub fn is_zero(&self) -> u8 {
        return ((self.0[0]
            | self.0[1]
            | self.0[2]
            | self.0[3]
            | self.0[4]
            | self.0[5]
            | self.0[6]
            | self.0[7])
            == 0) as u8;
    }

    pub fn negate(&self) -> Self {
        let nonzero = (0xFFFFFFFFu32 * ((self.is_zero() == 0) as u32)) as u64;
        let mut t = (!self.0[0]) as u64 + (MODULUS[0] + 1) as u64;
        let r0 = (t & nonzero) as u32;
        t >>= 32;
        t += (!self.0[1]) as u64 + MODULUS[1] as u64;
        let r1 = (t & nonzero) as u32;
        t >>= 32;
        t += (!self.0[2]) as u64 + MODULUS[2] as u64;
        let r2 = (t & nonzero) as u32;
        t >>= 32;
        t += (!self.0[3]) as u64 + MODULUS[3] as u64;
        let r3 = (t & nonzero) as u32;
        t >>= 32;
        t += (!self.0[4]) as u64 + MODULUS[4] as u64;
        let r4 = (t & nonzero) as u32;
        t >>= 32;
        t += (!self.0[5]) as u64 + MODULUS[5] as u64;
        let r5 = (t & nonzero) as u32;
        t >>= 32;
        t += (!self.0[6]) as u64 + MODULUS[6] as u64;
        let r6 = (t & nonzero) as u32;
        t >>= 32;
        t += (!self.0[7]) as u64 + MODULUS[7] as u64;
        let r7 = (t & nonzero) as u32;

        Self([r0, r1, r2, r3, r4, r5, r6, r7])
    }

    // TODO: compare performance with the old implementation from FieldElement, based on adc()
    pub fn add(&self, rhs: &Self) -> Self {
        let mut t = self.0[0] as u64 + rhs.0[0] as u64;
        // FIXME: `& 0xFFFFFFFFu64` is redundant
        let r0 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[1] as u64 + rhs.0[1] as u64;
        let r1 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[2] as u64 + rhs.0[2] as u64;
        let r2 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[3] as u64 + rhs.0[3] as u64;
        let r3 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[4] as u64 + rhs.0[4] as u64;
        let r4 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[5] as u64 + rhs.0[5] as u64;
        let r5 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[6] as u64 + rhs.0[6] as u64;
        let r6 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[7] as u64 + rhs.0[7] as u64;
        let r7 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;

        let r = Self([r0, r1, r2, r3, r4, r5, r6, r7]);
        let overflow = t as u8 + r.get_overflow();
        debug_assert!(overflow == 0 || overflow == 1);
        r.reduce(overflow)

        // TODO: the original returned overflow here, do we need it?
    }

    pub fn mul_wide(&self, rhs: &Self) -> WideScalar16x32 {
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

    pub fn mul(&self, rhs: &Self) -> Self {
        let wide_res = self.mul_wide(rhs);
        wide_res.reduce()
    }

    pub fn get_overflow(&self) -> u8 {
        let mut yes = 0u8;
        let mut no = 0u8;
        // FIXME: use subtle here
        no |= (self.0[7] < MODULUS[7]) as u8; /* No need for a > check. */
        no |= (self.0[6] < MODULUS[6]) as u8; /* No need for a > check. */
        no |= (self.0[5] < MODULUS[5]) as u8; /* No need for a > check. */
        no |= (self.0[4] < MODULUS[4]) as u8;
        yes |= (self.0[4] > MODULUS[4]) as u8 & !no;
        no |= (self.0[3] < MODULUS[3]) as u8 & !yes;
        yes |= (self.0[3] > MODULUS[3]) as u8 & !no;
        no |= (self.0[2] < MODULUS[2]) as u8 & !yes;
        yes |= (self.0[2] > MODULUS[2]) as u8 & !no;
        no |= (self.0[1] < MODULUS[1]) as u8 & !yes;
        yes |= (self.0[1] > MODULUS[1]) as u8 & !no;
        yes |= (self.0[0] >= MODULUS[0]) as u8 & !no;
        yes
    }

    pub fn reduce(&self, overflow: u8) -> Self {
        debug_assert!(overflow <= 1);

        // FIXME: use conditional select here
        let mut t = self.0[0] as u64 + ((overflow as u32) * NEG_MODULUS[0]) as u64;
        let r0 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[1] as u64 + ((overflow as u32) * NEG_MODULUS[1]) as u64;
        let r1 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[2] as u64 + ((overflow as u32) * NEG_MODULUS[2]) as u64;
        let r2 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[3] as u64 + ((overflow as u32) * NEG_MODULUS[3]) as u64;
        let r3 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[4] as u64 + ((overflow as u32) * NEG_MODULUS[4]) as u64;
        let r4 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[5] as u64;
        let r5 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[6] as u64;
        let r6 = (t & 0xFFFFFFFFu64) as u32;
        t >>= 32;
        t += self.0[7] as u64;
        let r7 = (t & 0xFFFFFFFFu64) as u32;

        Self([r0, r1, r2, r3, r4, r5, r6, r7])
    }

    pub fn rshift(&self, shift: usize) -> Self {
        let full_shifts = shift >> 5;
        let small_shift = shift & 0x1f;

        let mut res: [u32; 8] = [0u32; 8];

        if shift > 256 {
            return Self(res);
        }

        if small_shift == 0 {
            for i in 0..(8 - full_shifts) {
                res[i] = self.0[i + full_shifts];
            }
        } else {
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

    #[cfg(feature = "zeroize")]
    pub fn zeroize(&mut self) {
        self.0.as_mut().zeroize()
    }
}

impl From<u32> for Scalar8x32 {
    fn from(k: u32) -> Self {
        Self([k, 0, 0, 0, 0, 0, 0, 0])
    }
}

#[cfg(test)]
impl From<&BigUint> for Scalar8x32 {
    fn from(x: &BigUint) -> Self {
        let words = biguint_to_u32_array(x);
        Self::from_words(words).unwrap()
    }
}

#[cfg(test)]
impl ToBigUint for Scalar8x32 {
    fn to_biguint(&self) -> Option<BigUint> {
        Some(u32_array_to_biguint(&(self.0)))
    }
}

impl ConditionallySelectable for Scalar8x32 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self([
            u32::conditional_select(&a.0[0], &b.0[0], choice),
            u32::conditional_select(&a.0[1], &b.0[1], choice),
            u32::conditional_select(&a.0[2], &b.0[2], choice),
            u32::conditional_select(&a.0[3], &b.0[3], choice),
            u32::conditional_select(&a.0[4], &b.0[4], choice),
            u32::conditional_select(&a.0[5], &b.0[5], choice),
            u32::conditional_select(&a.0[6], &b.0[6], choice),
            u32::conditional_select(&a.0[7], &b.0[7], choice),
        ])
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

/** Add a to the number defined by (c0,c1,c2). c2 must never overflow. */
fn sumadd(a: u32, c0: u32, c1: u32, c2: u32) -> (u32, u32, u32) {
    let new_c0 = c0.wrapping_add(a); /* overflow is handled on the next line */
    let over: u32 = if new_c0 < a { 1 } else { 0 };
    let new_c1 = c1.wrapping_add(over); /* overflow is handled on the next line */
    let new_c2 = c2 + if new_c1 < over { 1 } else { 0 }; /* never overflows by contract */
    (new_c0, new_c1, new_c2)
}

/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
fn sumadd_fast(a: u32, c0: u32, c1: u32) -> (u32, u32) {
    let new_c0 = c0.wrapping_add(a); /* overflow is handled on the next line */
    let new_c1 = c1 + if new_c0 < a { 1 } else { 0 }; /* never overflows by contract (verified the next line) */
    debug_assert!((new_c1 != 0) | (new_c0 >= a));
    (new_c0, new_c1)
}

/** Add a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
fn muladd(a: u32, b: u32, c0: u32, c1: u32, c2: u32) -> (u32, u32, u32) {
    let t = (a as u64) * (b as u64);
    let th = (t >> 32) as u32; /* at most 0xFFFFFFFFFFFFFFFE */
    let tl = t as u32;

    let new_c0 = c0.wrapping_add(tl); /* overflow is handled on the next line */
    let new_th = th + if new_c0 < tl { 1 } else { 0 }; /* at most 0xFFFFFFFFFFFFFFFF */
    let new_c1 = c1.wrapping_add(new_th); /* overflow is handled on the next line */
    let new_c2 = c2 + if new_c1 < new_th { 1 } else { 0 }; /* never overflows by contract (verified in the next line) */
    debug_assert!((new_c1 >= new_th) || (new_c2 != 0));
    (new_c0, new_c1, new_c2)
}

/** Add a*b to the number defined by (c0,c1). c1 must never overflow. */
fn muladd_fast(a: u32, b: u32, c0: u32, c1: u32) -> (u32, u32) {
    let t = (a as u64) * (b as u64);
    let th = (t >> 32) as u32; /* at most 0xFFFFFFFFFFFFFFFE */
    let tl = t as u32;

    let new_c0 = c0.wrapping_add(tl); /* overflow is handled on the next line */
    // FIXME: constant time
    let new_th = th + if new_c0 < tl { 1 } else { 0 }; /* at most 0xFFFFFFFFFFFFFFFF */
    let new_c1 = c1 + new_th; /* never overflows by contract (verified in the next line) */
    debug_assert!(new_c1 >= new_th);
    (new_c0, new_c1)
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
        let s = Scalar8x32([r0, r1, r2, r3, r4, r5, r6, r7]);
        s.reduce((c as u8) + s.get_overflow())
    }
}
