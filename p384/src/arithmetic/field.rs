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

pub(super) use self::field_impl::fiat_p384_montgomery_domain_field_element as Fe;

use self::field_impl::*;
use super::LIMBS;
use crate::FieldBytes;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    bigint::{ArrayEncoding, Encoding, Integer, Limb, LimbUInt as Word, U384},
    subtle::{
        Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
        CtOption,
    },
    zeroize::DefaultIsZeroes,
};

/// Constant representing the modulus
/// p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1
pub(crate) const MODULUS: U384 = U384::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff");

/// An element in the finite field used for curve coordinates.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(super) U384);

impl FieldElement {
    /// Zero element.
    pub const ZERO: Self = Self(U384::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = Self(U384::from_be_hex("000000000000000000000000000000000000000000000000000000000000000100000000ffffffffffffffff00000001"));

    /// Parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns `None` if the byte array does not contain a big-endian integer in
    /// the range `[0, p)`.
    pub fn from_sec1(bytes: FieldBytes) -> CtOption<Self> {
        Self::from_uint(U384::from_be_byte_array(bytes))
    }

    /// Convert the given [`U384`] in canonical form into a [`FieldElement`]
    /// which internally uses Montgomery form.
    ///
    /// Returns `None` if the [`U384`] does not contain a big-endian integer in
    /// the range `[0, p)`.
    pub fn from_uint(w: U384) -> CtOption<Self> {
        let is_some = w.ct_lt(&MODULUS);

        // Convert w to Montgomery form: w * R^2 * R^-1 mod p = wR mod p
        CtOption::new(FieldElement(w).to_montgomery(), is_some)
    }

    /// Returns the SEC1 encoding of this field element.
    pub fn to_sec1(self) -> FieldBytes {
        self.to_canonical().0.to_be_byte_array()
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
        self.to_canonical().0.is_odd()
    }

    /// Returns `self + rhs`.
    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        self + rhs
    }

    /// Returns `self - rhs`.
    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        self - rhs
    }

    /// Returns `self - rhs` as well as a carry
    pub fn informed_subtract(&self, rhs: &Self) -> (Self, u8) {
        let mut out = Fe::default();
        fiat_p384_sub(&mut out, self.as_ref(), rhs.as_ref());
        let carry: bool = rhs.ct_gt(self).into();
        (Self(out.into()), carry as _)
    }

    /// Returns `self * rhs mod p`.
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
        let mut out = U384::default();
        fiat_p384_square(out.as_mut(), self.as_ref());
        Self(out)
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
        let t11 = t1 * t10;
        let t110 = t11.square();
        let t111 = t1 * t110;
        let t111000 = t111.sqn(3);
        let t111111 = t111 * t111000;
        let t1111110 = t111111.square();
        let t1111111 = t1 * t1111110;
        let x12 = t1111110.sqn(5) * t111111;
        let x24 = x12.sqn(12) * x12;
        let x31 = x24.sqn(7) * t1111111;
        let x32 = x31.square() * t1;
        let x63 = x32.sqn(31) * x31;
        let x126 = x63.sqn(63) * x63;
        let x252 = x126.sqn(126) * x126;
        let x255 = x252.sqn(3) * t111;
        let x = ((x255.sqn(33) * x32).sqn(64) * t1).sqn(30);
        CtOption::new(x, x.square().ct_eq(&t1))
    }

    /// Translate a field element out of the Montgomery domain.
    #[inline]
    pub fn to_canonical(self) -> Self {
        let mut out = U384::default();
        fiat_p384_from_montgomery(out.as_mut(), self.as_ref());
        Self(out)
    }

    /// Translate a field element into the Montgomery domain.
    #[inline]
    pub(crate) fn to_montgomery(self) -> Self {
        let mut out = U384::default();
        fiat_p384_to_montgomery(out.as_mut(), self.as_ref());
        Self(out)
    }

    /// Inversion.
    pub fn invert(&self) -> CtOption<Self> {
        const ITERATIONS: usize = (49 * U384::BIT_SIZE + 57) / 17;
        type XLimbs = [Word; LIMBS + 1];

        let mut d: Word = 1;
        let mut f = XLimbs::default();
        fiat_p384_msat(&mut f);

        let mut g = XLimbs::default();
        fiat_p384_from_montgomery((&mut g[..LIMBS]).try_into().unwrap(), self.as_ref());

        let mut r = Fe::default();
        fiat_p384_set_one(&mut r);

        let mut v = Fe::default();
        let mut precomp = Fe::default();
        fiat_p384_divstep_precomp(&mut precomp);

        let mut out1 = Word::default();
        let mut out2 = XLimbs::default();
        let mut out3 = XLimbs::default();
        let mut out4 = Fe::default();
        let mut out5 = Fe::default();

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

        let mut v_opp = Fe::default();
        fiat_p384_opp(&mut v_opp, &v);

        let s = ((f[f.len() - 1] >> (Limb::BIT_SIZE - 1)) & 1) as u8;
        let mut v_ = Fe::default();
        fiat_p384_selectznz(&mut v_, s, &v, &v_opp);

        let mut fe = Fe::default();
        fiat_p384_mul(&mut fe, &v_, &precomp);
        CtOption::new(Self(fe.into()), !self.is_zero())
    }
}

impl AsRef<Fe> for FieldElement {
    fn as_ref(&self) -> &Fe {
        self.0.as_ref()
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(U384::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConstantTimeLess for FieldElement {
    fn ct_lt(&self, other: &Self) -> Choice {
        self.0.ct_lt(&other.0)
    }
}

impl ConstantTimeGreater for FieldElement {
    fn ct_gt(&self, other: &Self) -> Choice {
        self.0.ct_gt(&other.0)
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        Self::ZERO
    }
}

impl DefaultIsZeroes for FieldElement {}

impl PartialEq for FieldElement {
    fn eq(&self, rhs: &Self) -> bool {
        self.0.ct_eq(&(rhs.0)).into()
    }
}

impl_field_op!(FieldElement, U384, Add, add, fiat_p384_add);
impl_field_op!(FieldElement, U384, Sub, sub, fiat_p384_sub);
impl_field_op!(FieldElement, U384, Mul, mul, fiat_p384_mul);

impl AddAssign for FieldElement {
    #[inline]
    fn add_assign(&mut self, rhs: FieldElement) {
        *self = *self + rhs;
    }
}

impl SubAssign for FieldElement {
    #[inline]
    fn sub_assign(&mut self, rhs: FieldElement) {
        *self = *self - rhs;
    }
}

impl MulAssign for FieldElement {
    #[inline]
    fn mul_assign(&mut self, rhs: FieldElement) {
        *self = *self * rhs;
    }
}

impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self {
        let mut out = U384::default();
        fiat_p384_opp(out.as_mut(), self.as_ref());
        Self(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{fiat_p384_to_montgomery, Fe, FieldElement};

    /// Test that the precomputed `FieldElement::ONE` constant is correct.
    #[test]
    fn one() {
        let mut one = Fe::default();
        one[0] = 1;

        let mut one_mont = Fe::default();
        fiat_p384_to_montgomery(&mut one_mont, &one);
        assert_eq!(FieldElement(one_mont.into()), FieldElement::ONE);
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
}
