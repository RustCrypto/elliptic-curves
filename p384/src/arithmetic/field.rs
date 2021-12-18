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

use self::field_impl::{
    fiat_p384_add, fiat_p384_montgomery_domain_field_element as FieldElementImpl, fiat_p384_mul,
    fiat_p384_opp, fiat_p384_square, fiat_p384_sub,
};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
    zeroize::DefaultIsZeroes,
};

/// An element in the finite field used for curve coordinates.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(FieldElementImpl);

impl FieldElement {
    /// Zero element.
    #[cfg(target_pointer_width = "32")]
    pub const ZERO: Self = Self([0u32; 12]);

    /// Zero element.
    #[cfg(target_pointer_width = "64")]
    pub const ZERO: Self = Self([0u64; 6]);

    /// Multiplicative identity.
    #[cfg(target_pointer_width = "32")]
    pub const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// Multiplicative identity.
    #[cfg(target_pointer_width = "64")]
    pub const ONE: Self = Self([1, 0, 0, 0, 0, 0]);

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
