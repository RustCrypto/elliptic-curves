#[cfg(test)]
use super::util::{biguint_to_u64_array, u64_array_to_biguint};
#[cfg(test)]
use num_bigint::{BigUint, ToBigUint};
#[cfg(test)]
use num_traits::cast::ToPrimitive;

use core::convert::TryInto;

use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::arithmetic::util::{adc, sbb};

/// The number of 64-bit limbs used to represent a [`Scalar`].
const LIMBS: usize = 4;

/// Constant representing the modulus
/// n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
pub const MODULUS: [u64; LIMBS] = [
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
];

/* Limbs of 2^256 minus the secp256k1 order. */
pub const NEG_MODULUS: [u64; LIMBS] = [!MODULUS[0] + 1, !MODULUS[1], 1, 0];

/// Constant representing the modulus / 2
const FRAC_MODULUS_2: [u64; LIMBS] = [
    0xDFE9_2F46_681B_20A0,
    0x5D57_6E73_57A4_501D,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct Scalar4x64([u64; LIMBS]);

/** Add a to the number defined by (c0,c1,c2). c2 must never overflow. */
fn sumadd(a: u64, c0: u64, c1: u64, c2: u64) -> (u64, u64, u64) {
    let new_c0 = c0.wrapping_add(a); /* overflow is handled on the next line */
    let over: u64 = if new_c0 < a { 1 } else { 0 };
    let new_c1 = c1.wrapping_add(over); /* overflow is handled on the next line */
    let new_c2 = c2 + if new_c1 < over { 1 } else { 0 }; /* never overflows by contract */
    (new_c0, new_c1, new_c2)
}

/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
fn sumadd_fast(a: u64, c0: u64, c1: u64) -> (u64, u64) {
    let new_c0 = c0.wrapping_add(a); /* overflow is handled on the next line */
    let new_c1 = c1 + if new_c0 < a { 1 } else { 0 }; /* never overflows by contract (verified the next line) */
    debug_assert!((new_c1 != 0) | (new_c0 >= a));
    (new_c0, new_c1)
}

/** Add a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
fn muladd(a: u64, b: u64, c0: u64, c1: u64, c2: u64) -> (u64, u64, u64) {
    let t = (a as u128) * (b as u128);
    let th = (t >> 64) as u64; /* at most 0xFFFFFFFFFFFFFFFE */
    let tl = t as u64;

    let new_c0 = c0.wrapping_add(tl); /* overflow is handled on the next line */
    let new_th = th + if new_c0 < tl { 1 } else { 0 }; /* at most 0xFFFFFFFFFFFFFFFF */
    let new_c1 = c1.wrapping_add(new_th); /* overflow is handled on the next line */
    let new_c2 = c2 + if new_c1 < new_th { 1 } else { 0 }; /* never overflows by contract (verified in the next line) */
    debug_assert!((new_c1 >= new_th) || (new_c2 != 0));
    (new_c0, new_c1, new_c2)
}

/** Add a*b to the number defined by (c0,c1). c1 must never overflow. */
fn muladd_fast(a: u64, b: u64, c0: u64, c1: u64) -> (u64, u64) {
    let t = (a as u128) * (b as u128);
    let th = (t >> 64) as u64; /* at most 0xFFFFFFFFFFFFFFFE */
    let tl = t as u64;

    let new_c0 = c0.wrapping_add(tl); /* overflow is handled on the next line */
    // FIXME: constant time
    let new_th = th + if new_c0 < tl { 1 } else { 0 }; /* at most 0xFFFFFFFFFFFFFFFF */
    let new_c1 = c1 + new_th; /* never overflows by contract (verified in the next line) */
    debug_assert!(new_c1 >= new_th);
    (new_c0, new_c1)
}

impl Scalar4x64 {
    /// Returns the zero scalar.
    pub const fn zero() -> Self {
        Self([0, 0, 0, 0])
    }

    /// Returns the multiplicative identity.
    pub const fn one() -> Self {
        Self([1, 0, 0, 0])
    }

    pub fn truncate_to_u32(&self) -> u32 {
        self.0[0] as u32
    }

    /// Attempts to parse the given byte array as an SEC-1-encoded scalar.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        let mut w = [0u64; LIMBS];

        // Interpret the bytes as a big-endian integer w.
        w[3] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        w[2] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        w[1] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        w[0] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());

        Self::from_words(w)
    }

    pub fn from_words(w: [u64; 4]) -> CtOption<Self> {
        // If w is in the range [0, n) then w - n will overflow, resulting in a borrow
        // value of 2^64 - 1.
        let (_, borrow) = sbb(w[0], MODULUS[0], 0);
        let (_, borrow) = sbb(w[1], MODULUS[1], borrow);
        let (_, borrow) = sbb(w[2], MODULUS[2], borrow);
        let (_, borrow) = sbb(w[3], MODULUS[3], borrow);
        let is_some = (borrow as u8) & 1;

        CtOption::new(Self(w), Choice::from(is_some))
    }

    /// Returns the SEC-1 encoding of this scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut ret = [0; 32];
        ret[0..8].copy_from_slice(&self.0[3].to_be_bytes());
        ret[8..16].copy_from_slice(&self.0[2].to_be_bytes());
        ret[16..24].copy_from_slice(&self.0[1].to_be_bytes());
        ret[24..32].copy_from_slice(&self.0[0].to_be_bytes());
        ret
    }

    /// Is this scalar greater than or equal to n / 2?
    pub fn is_high(&self) -> Choice {
        let (_, borrow) = sbb(self.0[0], FRAC_MODULUS_2[0], 0);
        let (_, borrow) = sbb(self.0[1], FRAC_MODULUS_2[1], borrow);
        let (_, borrow) = sbb(self.0[2], FRAC_MODULUS_2[2], borrow);
        let (_, borrow) = sbb(self.0[3], FRAC_MODULUS_2[3], borrow);
        (borrow & 1).ct_eq(&0)
    }

    // FIXME: use subtle
    pub fn is_zero(&self) -> u8 {
        return ((self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0) as u8;
    }

    // TODO: check if it's faster
    #[allow(dead_code)]
    pub fn neg(&self) -> Self {
        let (w0, borrow) = sbb(MODULUS[0], self.0[0], 0);
        let (w1, borrow) = sbb(MODULUS[1], self.0[1], borrow);
        let (w2, borrow) = sbb(MODULUS[2], self.0[2], borrow);
        let (w3, _) = sbb(MODULUS[3], self.0[3], borrow);

        let is_zero = self.0.ct_eq(&[0u64; LIMBS]);
        Self::conditional_select(&Self([w0, w1, w2, w3]), &Self::zero(), is_zero)
    }

    pub fn negate(&self) -> Self {
        // FIXME: use subtle
        let nonzero = (0xFFFFFFFFFFFFFFFFu64 * (self.is_zero() == 0) as u64) as u128;
        let mut t = (!self.0[0]) as u128 + (MODULUS[0] + 1) as u128;
        let r0 = t & nonzero;
        t >>= 64;
        t += (!self.0[1]) as u128 + MODULUS[1] as u128;
        let r1 = t & nonzero;
        t >>= 64;
        t += (!self.0[2]) as u128 + MODULUS[2] as u128;
        let r2 = t & nonzero;
        t >>= 64;
        t += (!self.0[3]) as u128 + MODULUS[3] as u128;
        let r3 = t & nonzero;
        Self([r0 as u64, r1 as u64, r2 as u64, r3 as u64])
    }

    // TODO: compare performance with the old implementation from FieldElement, based on adc()
    pub fn add(&self, rhs: &Self) -> Self {
        let mut t = (self.0[0] as u128) + (rhs.0[0] as u128);
        let r0 = t & 0xFFFFFFFFFFFFFFFFu128;
        t >>= 64;
        t += (self.0[1] as u128) + (rhs.0[1] as u128);
        let r1 = t & 0xFFFFFFFFFFFFFFFFu128;
        t >>= 64;
        t += (self.0[2] as u128) + (rhs.0[2] as u128);
        let r2 = t & 0xFFFFFFFFFFFFFFFFu128;
        t >>= 64;
        t += (self.0[3] as u128) + (rhs.0[3] as u128);
        let r3 = t & 0xFFFFFFFFFFFFFFFFu128;
        t >>= 64;
        let r = Self([r0 as u64, r1 as u64, r2 as u64, r3 as u64]);
        let overflow = t as u8 + r.get_overflow();
        debug_assert!(overflow == 0 || overflow == 1);

        // FIXME: a scalar should be normalized on creation; use from_words() or seomthing?
        r.reduce(overflow)

        // TODO: the original returned overflow here, do we need it?
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        let mut res = [0u64; 4];
        let mut borrow = 0;
        for i in 0..4 {
            let t = sbb(self.0[i], rhs.0[i], borrow);
            res[i] = t.0;
            borrow = t.1;
        }

        // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the
        // modulus.
        let mut carry = 0;
        for i in 0..4 {
            let t = adc(res[i], MODULUS[i] & borrow, carry);
            res[i] = t.0;
            carry = t.1;
        }

        Self(res)
    }

    pub fn mul_wide(&self, rhs: &Self) -> WideScalar8x64 {
        /* 160 bit accumulator. */

        let c0 = 0;
        let c1 = 0;
        let c2 = 0;

        /* l[0..7] = a[0..3] * b[0..3]. */
        // FIXME: `muladd()` always receives c2 == 0; can we optimize that?
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
        let (c0, c1, c2) = muladd(self.0[1], rhs.0[3], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[2], rhs.0[2], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[3], rhs.0[1], c0, c1, c2);
        let (l4, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(self.0[2], rhs.0[3], c0, c1, c2);
        let (c0, c1, c2) = muladd(self.0[3], rhs.0[2], c0, c1, c2);
        let (l5, c0, c1, _c2) = (c0, c1, c2, 0);
        let (c0, c1) = muladd_fast(self.0[3], rhs.0[3], c0, c1);
        let (l6, c0, _c1) = (c0, c1, 0);
        let l7 = c0;

        WideScalar8x64([l0, l1, l2, l3, l4, l5, l6, l7])
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        let wide_res = self.mul_wide(rhs);
        wide_res.reduce()
    }

    pub fn get_overflow(&self) -> u8 {
        let mut yes = 0u8;
        let mut no = 0u8;
        // FIXME: use subtle here
        no |= (self.0[3] < MODULUS[3]) as u8; /* No need for a > check. */
        no |= (self.0[2] < MODULUS[2]) as u8;
        yes |= (self.0[2] > MODULUS[2]) as u8 & !no;
        no |= (self.0[1] < MODULUS[1]) as u8;
        yes |= (self.0[1] > MODULUS[1]) as u8 & !no;
        yes |= (self.0[0] >= MODULUS[0]) as u8 & !no;
        yes
    }

    pub fn reduce(&self, overflow: u8) -> Self {
        debug_assert!(overflow <= 1);

        // FIXME: use conditional select here
        let mut t = (self.0[0] as u128) + ((overflow as u64 * NEG_MODULUS[0]) as u128);
        let r0 = (t & 0xFFFFFFFFFFFFFFFFu128) as u64;
        t >>= 64;
        t += (self.0[1] as u128) + ((overflow as u64 * NEG_MODULUS[1]) as u128);
        let r1 = (t & 0xFFFFFFFFFFFFFFFFu128) as u64;
        t >>= 64;
        t += (self.0[2] as u128) + ((overflow as u64 * NEG_MODULUS[2]) as u128);
        let r2 = (t & 0xFFFFFFFFFFFFFFFFu128) as u64;
        t >>= 64;
        t += self.0[3] as u128;
        let r3 = (t & 0xFFFFFFFFFFFFFFFFu128) as u64;
        // TODO: the original returned overflow here, do we need it?

        Self([r0, r1, r2, r3])
    }

    pub fn rshift(&self, shift: usize) -> Self {
        let full_shifts = shift >> 6;
        let small_shift = shift & 0x3f;

        let mut res: [u64; 4] = [0, 0, 0, 0];

        if shift > 256 {
            return Self(res);
        }

        if small_shift == 0 {
            #[allow(clippy::needless_range_loop)]
            #[allow(clippy::manual_memcpy)]
            for i in 0..(4 - full_shifts) {
                res[i] = self.0[i + full_shifts];
            }
        } else {
            #[allow(clippy::needless_range_loop)]
            for i in 0..(4 - full_shifts) {
                let mut lo = self.0[i + full_shifts] >> small_shift;
                if i < 3 - full_shifts {
                    lo |= self.0[i + full_shifts + 1] << (64 - small_shift);
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

impl From<u64> for Scalar4x64 {
    fn from(k: u64) -> Self {
        Scalar4x64([k, 0, 0, 0])
    }
}

impl From<u32> for Scalar4x64 {
    fn from(k: u32) -> Self {
        Scalar4x64([k as u64, 0, 0, 0])
    }
}

#[cfg(test)]
impl From<&BigUint> for Scalar4x64 {
    fn from(x: &BigUint) -> Self {
        let words = biguint_to_u64_array(x);
        Scalar4x64::from_words(words).unwrap()
    }
}

#[cfg(test)]
impl ToBigUint for Scalar4x64 {
    fn to_biguint(&self) -> Option<BigUint> {
        Some(u64_array_to_biguint(&(self.0)))
    }
}

impl ConditionallySelectable for Scalar4x64 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar4x64([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

impl ConstantTimeEq for Scalar4x64 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WideScalar8x64([u64; 8]);

impl WideScalar8x64 {
    #[cfg(feature = "rand")]
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut w = [0u64; 8];
        for i in 0..8 {
            w[i] = u64::from_be_bytes(bytes[((7 - i) * 8)..((7 - i) * 8 + 8)].try_into().unwrap());
        }
        Self(w)
    }

    pub fn reduce(&self) -> Scalar4x64 {
        let n0 = self.0[4];
        let n1 = self.0[5];
        let n2 = self.0[6];
        let n3 = self.0[7];

        /* Reduce 512 bits into 385. */
        /* m[0..6] = self[0..3] + n[0..3] * NEG_MODULUS. */
        // FIXME: some functions receive 0 as arguments; can it be optimized?
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
        let (c0, c1, c2) = sumadd(n0, c0, c1, c2);
        let (m2, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = sumadd(self.0[3], c0, c1, c2);
        let (c0, c1, c2) = muladd(n3, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(n2, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = sumadd(n1, c0, c1, c2);
        let (m3, c0, c1, c2) = (c0, c1, c2, 0);
        let (c0, c1, c2) = muladd(n3, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = sumadd(n2, c0, c1, c2);
        let (m4, c0, c1, _c2) = (c0, c1, c2, 0);
        let (c0, c1) = sumadd_fast(n3, c0, c1);
        let (m5, c0, _c1) = (c0, c1, 0);
        debug_assert!(c0 <= 1);
        let m6 = c0; // FIXME: as u32 in the original, but it's used in muladd() anyway;

        /* Reduce 385 bits into 258. */
        /* p[0..4] = m[0..3] + m[4..6] * NEG_MODULUS. */
        let c0 = m0;
        let c1 = 0;
        let c2 = 0;
        let (c0, c1) = muladd_fast(m4, NEG_MODULUS[0], c0, c1);
        let (p0, c0, c1) = (c0, c1, 0);
        let (c0, c1) = sumadd_fast(m1, c0, c1);
        let (c0, c1, c2) = muladd(m5, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(m4, NEG_MODULUS[1], c0, c1, c2);
        let (p1, c0, c1) = (c0, c1, 0);
        let (c0, c1, c2) = sumadd(m2, c0, c1, c2);
        let (c0, c1, c2) = muladd(m6, NEG_MODULUS[0], c0, c1, c2);
        let (c0, c1, c2) = muladd(m5, NEG_MODULUS[1], c0, c1, c2);
        let (c0, c1, c2) = sumadd(m4, c0, c1, c2);
        let (p2, c0, c1, _c2) = (c0, c1, c2, 0);
        let (c0, c1) = sumadd_fast(m3, c0, c1);
        let (c0, c1) = muladd_fast(m6, NEG_MODULUS[1], c0, c1);
        let (c0, c1) = sumadd_fast(m5, c0, c1);
        let (p3, c0, _c1) = (c0, c1, 0);
        let p4 = c0 + m6; // FIXME: as u32 in the original, but it has to be converted later anyway;
        debug_assert!(p4 <= 2);

        /* Reduce 258 bits into 256. */
        /* r[0..3] = p[0..3] + p[4] * NEG_MODULUS. */
        let mut c = (p0 as u128) + (NEG_MODULUS[0] as u128) * (p4 as u128);
        let r0 = (c & 0xFFFFFFFFFFFFFFFFu128) as u64;
        c >>= 64;
        c += (p1 as u128) + (NEG_MODULUS[1] as u128) * (p4 as u128);
        let r1 = (c & 0xFFFFFFFFFFFFFFFFu128) as u64;
        c >>= 64;
        c += (p2 as u128) + (p4 as u128);
        let r2 = (c & 0xFFFFFFFFFFFFFFFFu128) as u64;
        c >>= 64;
        c += p3 as u128;
        let r3 = (c & 0xFFFFFFFFFFFFFFFFu128) as u64;
        c >>= 64;

        /* Final reduction of r. */
        let s = Scalar4x64([r0, r1, r2, r3]);
        s.reduce((c as u8) + s.get_overflow())
    }
}

#[cfg(test)]
impl From<&BigUint> for WideScalar8x64 {
    fn from(x: &BigUint) -> Self {
        let mask = BigUint::from(u64::MAX);
        let w0 = (x & &mask).to_u64().unwrap();
        let w1 = ((x >> 64) as BigUint & &mask).to_u64().unwrap();
        let w2 = ((x >> 128) as BigUint & &mask).to_u64().unwrap();
        let w3 = ((x >> 192) as BigUint & &mask).to_u64().unwrap();
        let w4 = ((x >> 256) as BigUint & &mask).to_u64().unwrap();
        let w5 = ((x >> 320) as BigUint & &mask).to_u64().unwrap();
        let w6 = ((x >> 384) as BigUint & &mask).to_u64().unwrap();
        let w7 = ((x >> 448) as BigUint & &mask).to_u64().unwrap();
        Self([w0, w1, w2, w3, w4, w5, w6, w7])
    }
}

impl ConstantTimeEq for WideScalar8x64 {
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

impl PartialEq for WideScalar8x64 {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
