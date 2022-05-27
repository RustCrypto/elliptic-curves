//! Field arithmetic modulo p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1
//!
//! Arithmetic implementations are extracted Rust code from the Coq fiat-crypto
//! libraries.
//!
//! # License
//!
//! Copyright (c) 2015-2020 the fiat-crypto authors
//!
//! fiat-crypto is distributed under the terms of the MIT License, the
//! Apache License (Version 2.0), and the BSD 1-Clause License;
//! users may pick which license to apply.

#![allow(
    clippy::should_implement_trait,
    clippy::suspicious_op_assign_impl,
    clippy::unused_unit,
    clippy::unnecessary_cast,
    clippy::too_many_arguments,
    clippy::identity_op
)]

#[cfg_attr(target_pointer_width = "32", path = "field/p384_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/p384_64.rs")]
#[allow(dead_code)]
#[rustfmt::skip]
mod field_impl;

pub(super) use self::field_impl::fiat_p384_montgomery_domain_field_element as FieldElementImpl;

use self::field_impl::*;
use super::LIMBS;
use crate::FieldBytes;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
};

/// Type used to represent a limb.
#[cfg(target_pointer_width = "32")]
type Limb = u32;
/// Type used to represent a limb.
#[cfg(target_pointer_width = "64")]
type Limb = u64;

/// Constant representing the modulus
/// p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1
#[cfg(target_pointer_width = "32")]
pub(crate) const MODULUS: FieldElement = FieldElement([
    0xffffffff, 0x00000000, 0x00000000, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
]);
/// Constant representing the modulus
/// p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1
#[cfg(target_pointer_width = "64")]
pub(crate) const MODULUS: FieldElement = FieldElement([
    0x00000000_ffffffff,
    0xffffffff_00000000,
    0xffffffff_fffffffe,
    0xffffffff_ffffffff,
    0xffffffff_ffffffff,
    0xffffffff_ffffffff,
]);

/// An element in the finite field used for curve coordinates.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(super) FieldElementImpl);

impl FieldElement {
    /// Multiplicative identity.
    #[cfg(target_pointer_width = "32")]
    pub const ONE: Self = Self([
        0x1, 0xffffffff, 0xffffffff, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ]);
    /// Multiplicative identity.
    #[cfg(target_pointer_width = "64")]
    pub const ONE: Self = Self([0xffffffff00000001, 0xffffffff, 0x1, 0x0, 0x0, 0x0]);

    /// Zero element.
    pub const ZERO: Self = Self([0; LIMBS]);

    pub fn from_limbs(limbs: [Limb; LIMBS]) -> Self {
        FieldElement(limbs)
    }

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns `None` if the byte array does not contain a big-endian integer in
    /// the range `[0, p)`.
    #[cfg(target_pointer_width = "32")]
    pub fn from_sec1(bytes: &FieldBytes) -> CtOption<Self> {
        let mut w = [Limb::default(); LIMBS];

        // Interpret the bytes as a big-endian integer w.
        w[11] = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        w[10] = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        w[9] = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        w[8] = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        w[7] = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        w[6] = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        w[5] = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        w[4] = u32::from_be_bytes(bytes[28..32].try_into().unwrap());
        w[3] = u32::from_be_bytes(bytes[32..36].try_into().unwrap());
        w[2] = u32::from_be_bytes(bytes[36..40].try_into().unwrap());
        w[1] = u32::from_be_bytes(bytes[40..44].try_into().unwrap());
        w[0] = u32::from_be_bytes(bytes[44..48].try_into().unwrap());

        // If w is in the range [0, p) then w - p will overflow, resulting in a borrow
        // value of 2^64 - 1.
        let (_, borrow) = sbb(w[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb(w[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb(w[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb(w[3], MODULUS.0[3], borrow);
        let (_, borrow) = sbb(w[4], MODULUS.0[4], borrow);
        let (_, borrow) = sbb(w[5], MODULUS.0[5], borrow);
        let (_, borrow) = sbb(w[0], MODULUS.0[6], borrow);
        let (_, borrow) = sbb(w[1], MODULUS.0[7], borrow);
        let (_, borrow) = sbb(w[2], MODULUS.0[8], borrow);
        let (_, borrow) = sbb(w[3], MODULUS.0[9], borrow);
        let (_, borrow) = sbb(w[4], MODULUS.0[10], borrow);
        let (_, borrow) = sbb(w[5], MODULUS.0[11], borrow);
        let is_some = (borrow as u8) & 1;

        // Convert w to Montgomery form: w * R^2 * R^-1 mod p = wR mod p
        CtOption::new(FieldElement(w).to_montgomery(), Choice::from(is_some))
    }

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns `None` if the byte array does not contain a big-endian integer in
    /// the range `[0, p)`.
    #[cfg(target_pointer_width = "64")]
    pub fn from_sec1(bytes: &FieldBytes) -> CtOption<Self> {
        let mut w = [Limb::default(); LIMBS];

        // Interpret the bytes as a big-endian integer w.
        w[5] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        w[4] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        w[3] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        w[2] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
        w[1] = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
        w[0] = u64::from_be_bytes(bytes[40..48].try_into().unwrap());

        // If w is in the range [0, p) then w - p will overflow, resulting in a borrow
        // value of 2^64 - 1.
        let (_, borrow) = sbb(w[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb(w[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb(w[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb(w[3], MODULUS.0[3], borrow);
        let (_, borrow) = sbb(w[4], MODULUS.0[4], borrow);
        let (_, borrow) = sbb(w[5], MODULUS.0[5], borrow);
        let is_some = (borrow as u8) & 1;

        // Convert w to Montgomery form: w * R^2 * R^-1 mod p = wR mod p
        CtOption::new(FieldElement(w).to_montgomery(), Choice::from(is_some))
    }

    /// Returns the SEC1 encoding of this field element.
    #[cfg(target_pointer_width = "32")]
    pub fn to_sec1(self) -> FieldBytes {
        // Convert from Montgomery form to canonical form
        let tmp = self.to_canonical();

        let mut ret = FieldBytes::default();
        ret[0..4].copy_from_slice(&tmp.0[11].to_be_bytes());
        ret[4..8].copy_from_slice(&tmp.0[10].to_be_bytes());
        ret[8..12].copy_from_slice(&tmp.0[9].to_be_bytes());
        ret[12..16].copy_from_slice(&tmp.0[8].to_be_bytes());
        ret[16..20].copy_from_slice(&tmp.0[7].to_be_bytes());
        ret[20..24].copy_from_slice(&tmp.0[6].to_be_bytes());
        ret[24..28].copy_from_slice(&tmp.0[5].to_be_bytes());
        ret[28..32].copy_from_slice(&tmp.0[4].to_be_bytes());
        ret[32..36].copy_from_slice(&tmp.0[3].to_be_bytes());
        ret[36..40].copy_from_slice(&tmp.0[2].to_be_bytes());
        ret[40..44].copy_from_slice(&tmp.0[1].to_be_bytes());
        ret[44..48].copy_from_slice(&tmp.0[0].to_be_bytes());
        ret
    }

    /// Returns the SEC1 encoding of this field element.
    #[cfg(target_pointer_width = "64")]
    pub fn to_sec1(self) -> FieldBytes {
        // Convert from Montgomery form to canonical form
        let tmp = self.to_canonical();

        let mut ret = FieldBytes::default();
        ret[0..8].copy_from_slice(&tmp.0[5].to_be_bytes());
        ret[8..16].copy_from_slice(&tmp.0[4].to_be_bytes());
        ret[16..24].copy_from_slice(&tmp.0[3].to_be_bytes());
        ret[24..32].copy_from_slice(&tmp.0[2].to_be_bytes());
        ret[32..40].copy_from_slice(&tmp.0[1].to_be_bytes());
        ret[40..48].copy_from_slice(&tmp.0[0].to_be_bytes());
        ret
    }

    /// Determine if this `FieldElement` is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Determine if this `FieldElement` is odd in the SEC1 sense: `self mod 2
    /// == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        let bytes = self.to_sec1();
        (bytes[47] & 1).into()
    }

    /// Returns self + rhs.
    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        self + rhs
    }

    /// Returns self - rhs.
    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        self - rhs
    }

    /// Returns self - rhs as well as a carry
    pub fn informed_subtract(&self, rhs: &Self) -> (Self, u8) {
        let mut out = Self::ZERO;
        fiat_p384_sub(&mut out.0, &self.0, &rhs.0);
        let carry: bool = rhs.ct_gt(self).into();
        (out, carry as _)
    }

    /// Returns self * rhs mod p.
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        self * rhs
    }

    /// Returns -self.
    #[inline]
    pub fn neg(self) -> Self {
        -self
    }

    /// Returns 2*self.
    ///
    /// Doubles the magnitude.
    #[inline]
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Returns self * self.
    #[inline]
    pub fn square(&self) -> Self {
        let mut out = Self::ZERO;
        fiat_p384_square(&mut out.0, &self.0);
        out
    }

    /// Returns self^(2^n) mod p
    fn sqn(&self, n: usize) -> Self {
        let mut x = *self;
        for _ in 0..n {
            x = x.square();
        }
        x
    }

    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // p mod 4 = 3 -> compute sqrt(x) using x^((p+1)/4) =
        // x^9850501549098619803069760025035903451269934817616361666987073351061430442874217582261816522064734500465401743278080
        let t1 = *self;
        let t10 = t1.square();
        let t11 = t1 * &t10;
        let t110 = t11.square();
        let t111 = t1 * &t110;
        let t111000 = t111.sqn(3);
        let t111111 = t111 * &t111000;
        let t1111110 = t111111.square();
        let t1111111 = t1 * &t1111110;
        let x12 = t1111110.sqn(5) * &t111111;
        let x24 = x12.sqn(12) * &x12;
        let x31 = x24.sqn(7) * &t1111111;
        let x32 = x31.square() * &t1;
        let x63 = x32.sqn(31) * &x31;
        let x126 = x63.sqn(63) * &x63;
        let x252 = x126.sqn(126) * &x126;
        let x255 = x252.sqn(3) * &t111;
        let x = ((x255.sqn(33) * &x32).sqn(64) * &t1).sqn(30);
        CtOption::new(x, x.square().ct_eq(&t1))
    }

    /// Translate a field element out of the Montgomery domain.
    #[inline]
    pub fn to_canonical(self) -> Self {
        let mut out = Self::ZERO;
        fiat_p384_from_montgomery(&mut out.0, &self.0);
        out
    }

    /// Translate a field element into the Montgomery domain.
    #[inline]
    pub(crate) fn to_montgomery(self) -> Self {
        let mut out = Self::ZERO;
        fiat_p384_to_montgomery(&mut out.0, &self.0);
        out
    }

    /// Inversion.
    #[cfg(target_pointer_width = "32")]
    pub fn invert(&self) -> CtOption<Self> {
        todo!()
    }

    /// Inversion.
    #[cfg(target_pointer_width = "64")]
    pub fn invert(&self) -> CtOption<Self> {
        let limbs = &self.0;
        type Fe = fiat_p384_montgomery_domain_field_element;
        type Word = u64;
        const LEN_PRIME: usize = 384;

        const WORD_BITS: usize = 64;
        const LIMBS_WORDS: usize = 6;
        type XLimbs = [Word; LIMBS_WORDS + 1];

        fn one() -> Fe {
            let mut fe = Fe::default();
            fiat_p384_set_one(&mut fe);
            fe
        }

        const ITERATIONS: usize = (49 * LEN_PRIME + if LEN_PRIME < 46 { 80 } else { 57 }) / 17;
        let mut d: Word = 1;
        let mut f: XLimbs = Default::default();
        fiat_p384_msat(&mut f);

        let mut g: XLimbs = Default::default();
        let mut g_: Fe = Default::default();
        fiat_p384_from_montgomery(&mut g_, limbs);
        g[..g_.len()].copy_from_slice(&g_);

        let mut r = one();
        let mut v: Fe = Default::default();

        let mut precomp: Fe = Default::default();
        fiat_p384_divstep_precomp(&mut precomp);

        let mut out1: Word = Default::default();
        let mut out2: XLimbs = Default::default();
        let mut out3: XLimbs = Default::default();
        let mut out4: Fe = Default::default();
        let mut out5: Fe = Default::default();

        let mut i: usize = 0;
        while i < ITERATIONS - ITERATIONS % 2 {
            fiat_p384_divstep(
                &mut out1, &mut out2, &mut out3, &mut out4, &mut out5, d, &f, &g, &v, &r,
            );
            fiat_p384_divstep(
                &mut d, &mut f, &mut g, &mut v, &mut r, out1, &out2, &out3, &out4, &out5,
            );
            i += 2;
        }
        if ITERATIONS % 2 != 0 {
            fiat_p384_divstep(
                &mut out1, &mut out2, &mut out3, &mut out4, &mut out5, d, &f, &g, &v, &r,
            );
            v = out4;
            f = out2;
        }
        let mut v_opp: Fe = Default::default();
        fiat_p384_opp(&mut v_opp, &v);
        let s = ((f[f.len() - 1] >> (WORD_BITS - 1)) & 1) as u8;
        let mut v_: Fe = Default::default();
        fiat_p384_selectznz(&mut v_, s, &v, &v_opp);
        let mut fe: Fe = Default::default();
        fiat_p384_mul(&mut fe, &v_, &precomp);
        CtOption::new(FieldElement::from(fe), !self.is_zero())
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, rhs: &Self) -> bool {
        self.0.ct_eq(&(rhs.0)).into()
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = Self::ZERO;

        for i in 0..out.0.len() {
            out.0[i] = ConditionallySelectable::conditional_select(&a.0[i], &b.0[i], choice);
        }

        out
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.0
            .iter()
            .zip(rhs.0.iter())
            .fold(Choice::from(1), |choice, (a, b)| choice & a.ct_eq(b))
    }
}

impl FieldElement {
    fn from_field_bytes(bytes: FieldBytes) -> CtOption<Self> {
        let mut non_mont = Default::default();
        fiat_p384_from_bytes(&mut non_mont, bytes.as_ref());
        let mut mont = Default::default();
        fiat_p384_to_montgomery(&mut mont, &non_mont);
        let out = FieldElement(mont);
        CtOption::new(out, 1.into())
    }

    fn ct_gt(&self, other: &Self) -> Choice {
        // not CT
        let mut out = Choice::from(0);
        for (x, y) in self.0.iter().zip(other.0.iter()) {
            if x > y {
                out = Choice::from(1);
            }
        }
        out
    }
}

impl DefaultIsZeroes for FieldElement {}

use elliptic_curve::bigint::Encoding;

use crate::U384;

impl From<U384> for FieldElement {
    fn from(w: U384) -> Self {
        let bytes = w.to_be_bytes();
        let out = Self::from_field_bytes(FieldBytes::from(bytes));
        out.unwrap()
    }
}

#[cfg(target_pointer_width = "32")]
impl From<[u32; 12]> for FieldElement {
    fn from(w: [u32; 12]) -> Self {
        FieldElement::from_limbs(w)
    }
}

#[cfg(target_pointer_width = "64")]
impl From<[u64; 6]> for FieldElement {
    fn from(w: [u64; 6]) -> Self {
        FieldElement::from_limbs(w)
    }
}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, rhs: &FieldElement) -> FieldElement {
        let mut out = FieldElement::ZERO;
        fiat_p384_add(&mut out.0, &self.0, &rhs.0);
        out
    }
}

impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, rhs: &FieldElement) -> FieldElement {
        let mut out = FieldElement::ZERO;
        fiat_p384_add(&mut out.0, &self.0, &rhs.0);
        out
    }
}

impl AddAssign for FieldElement {
    fn add_assign(&mut self, rhs: FieldElement) {
        *self = *self + &rhs;
    }
}

impl Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn sub(self, rhs: &FieldElement) -> FieldElement {
        let mut out = FieldElement::ZERO;
        fiat_p384_sub(&mut out.0, &self.0, &rhs.0);
        out
    }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, rhs: &FieldElement) -> FieldElement {
        let mut out = FieldElement::ZERO;
        fiat_p384_sub(&mut out.0, &self.0, &rhs.0);
        out
    }
}

impl SubAssign for FieldElement {
    fn sub_assign(&mut self, rhs: FieldElement) {
        *self = *self + &rhs;
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        let mut out = FieldElement::ZERO;
        fiat_p384_mul(&mut out.0, &self.0, &rhs.0);
        out
    }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        let mut out = FieldElement::ZERO;
        fiat_p384_mul(&mut out.0, &self.0, &rhs.0);
        out
    }
}

impl MulAssign for FieldElement {
    fn mul_assign(&mut self, rhs: FieldElement) {
        *self = *self * &rhs;
    }
}

impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self {
        let mut out = FieldElement::ZERO;
        fiat_p384_opp(&mut out.0, &self.0);
        out
    }
}

/// Computes `a - (b + borrow)`, returning the result and the new borrow.
#[cfg(target_pointer_width = "32")]
#[inline(always)]
pub const fn sbb(a: u32, b: u32, borrow: u32) -> (u32, u32) {
    let ret = (a as u64).wrapping_sub((b as u64) + ((borrow >> 31) as u64));
    (ret as u32, (ret >> 32) as u32)
}

/// Computes `a - (b + borrow)`, returning the result and the new borrow.
#[cfg(target_pointer_width = "64")]
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

/// Basic tests that field inversion works.
#[test]
fn invert() {
    let one = FieldElement::ONE;
    assert_eq!(one.invert().unwrap(), one);

    let three = one + &one + &one;
    let inv_three = three.invert().unwrap();
    assert_eq!(three * &inv_three, one);

    let minus_three = -three;
    let inv_minus_three = minus_three.invert().unwrap();
    assert_eq!(inv_minus_three, -inv_three);
    assert_eq!(three * &inv_minus_three, -one);
}

#[test]
fn sqrt() {
    let one = FieldElement::ONE;
    let two = one + &one;
    let four = two.square();
    assert_eq!(four.sqrt().unwrap(), two);
}
