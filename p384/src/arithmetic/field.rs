//! Field arithmetic modulo p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1
//!
//! Arithmetic implementations are extracted Rust code from the Coq fiat-crypto libraries.
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

use self::field_impl::{
    fiat_p384_add, fiat_p384_from_montgomery, fiat_p384_mul, fiat_p384_opp, fiat_p384_square,
    fiat_p384_sub, fiat_p384_to_montgomery,
};
use crate::FieldBytes;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
};

/// Type used to represent a limb.
// TODO(tarcieri): hardcoded for 64-bit; add 32-bit support
type Limb = u64;

/// Number of limbs used to represent a field element.
// TODO(tarcieri): hardcoded for 64-bit; add 32-bit support
const LIMBS: usize = 6;

/// Constant representing the modulus
/// p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1
// TODO(tarcieri): convert to Montgomery form?
pub(crate) const MODULUS: FieldElement = FieldElement([
    0x00000000ffffffff,
    0xffffffff00000000,
    0xfffffffffffffffe,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
]);

/// An element in the finite field used for curve coordinates.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(super) FieldElementImpl);

impl FieldElement {
    /// Zero element.
    pub const ZERO: Self = Self([0; LIMBS]);

    /// Multiplicative identity.
    #[cfg(target_pointer_width = "32")]
    pub const ONE: Self = Self([
        0x1, 0xffffffff, 0xffffffff, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ]);

    /// Multiplicative identity.
    #[cfg(target_pointer_width = "64")]
    pub const ONE: Self = Self([0xffffffff00000001, 0xffffffff, 0x1, 0x0, 0x0, 0x0]);

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: &FieldBytes) -> CtOption<Self> {
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
    pub fn to_bytes(self) -> FieldBytes {
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

    /// Determine if this `FieldElement` is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        Choice::from((self.0[0] % 2) as u8)
    }

    /// Returns self + rhs.
    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = Self::ZERO;
        fiat_p384_add(&mut out.0, &self.0, &rhs.0);
        out
    }

    /// Returns self - rhs.
    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut out = Self::ZERO;
        fiat_p384_sub(&mut out.0, &self.0, &rhs.0);
        out
    }

    /// Returns self * rhs mod p.
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut out = Self::ZERO;
        fiat_p384_mul(&mut out.0, &self.0, &rhs.0);
        out
    }

    /// Returns -self.
    #[inline]
    pub fn neg(self) -> Self {
        let mut out = Self::ZERO;
        fiat_p384_opp(&mut out.0, &self.0);
        out
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

    /// Returns the square root of self mod p, or `None` if no square root exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        todo!()
    }

    /// Translate a field element out of the Montgomery domain.
    #[inline]
    fn to_canonical(self) -> Self {
        let mut out = Self::ZERO;
        fiat_p384_from_montgomery(&mut out.0, &self.0);
        out
    }

    /// Translate a field element into the Montgomery domain.
    #[inline]
    fn to_montgomery(self) -> Self {
        let mut out = Self::ZERO;
        fiat_p384_to_montgomery(&mut out.0, &self.0);
        out
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

impl DefaultIsZeroes for FieldElement {}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, rhs: &FieldElement) -> FieldElement {
        self.add(rhs)
    }
}

impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::add(&self, rhs)
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
        self.sub(rhs)
    }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::sub(&self, rhs)
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
        self.mul(rhs)
    }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::mul(&self, rhs)
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
        self.neg()
    }
}

/// Computes `a - (b + borrow)`, returning the result and the new borrow.
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}
