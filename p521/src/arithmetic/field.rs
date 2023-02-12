//! Field arithmetic modulo p = 2^{521} − 1
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
    clippy::identity_op,
    rustdoc::bare_urls
)]
// TODO(tarcieri): use all variables
#![allow(unused_variables)]

// TODO(tarcieri): 32-bit backend?
#[path = "field/p521_64.rs"]
mod field_impl;
mod loose;

pub(crate) use self::loose::LooseFieldElement;

use self::field_impl::*;
use crate::{FieldBytes, NistP521, U576};
use core::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::{
    ff::{self, Field, PrimeField},
    generic_array::GenericArray,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess, CtOption},
    zeroize::DefaultIsZeroes,
    FieldBytesEncoding,
};

/// Constant representing the modulus serialized as hex.
/// p = 2^{521} − 1
const MODULUS_HEX: &str = "00000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

const MODULUS: U576 = U576::from_be_hex(MODULUS_HEX);

/// Element of the secp521r1 base field used for curve coordinates.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(fiat_p521_tight_field_element);

impl FieldElement {
    /// Zero element.
    pub const ZERO: Self = Self::from_u64(0);

    /// Multiplicative identity.
    pub const ONE: Self = Self::from_u64(1);

    /// Number of bytes in the serialized representation.
    const BYTES: usize = 66;

    /// Create a [`FieldElement`] from a canonical big-endian representation.
    pub fn from_bytes(repr: &FieldBytes) -> CtOption<Self> {
        let uint = <U576 as FieldBytesEncoding<NistP521>>::decode_field_bytes(repr);
        Self::from_uint(uint)
    }

    /// Decode [`FieldElement`] from a big endian byte slice.
    pub fn from_slice(slice: &[u8]) -> elliptic_curve::Result<Self> {
        if slice.len() != Self::BYTES {
            return Err(elliptic_curve::Error);
        }

        Option::from(Self::from_bytes(GenericArray::from_slice(slice))).ok_or(elliptic_curve::Error)
    }

    /// Decode [`FieldElement`] from [`U576`].
    pub fn from_uint(uint: U576) -> CtOption<Self> {
        let is_some = uint.ct_lt(&MODULUS);
        CtOption::new(Self::from_uint_unchecked(uint), is_some)
    }

    /// Parse a [`FieldElement`] from big endian hex-encoded bytes.
    ///
    /// Does *not* perform a check that the field element does not overflow the order.
    ///
    /// This method is primarily intended for defining internal constants.
    #[allow(dead_code)]
    pub(crate) const fn from_hex(hex: &str) -> Self {
        Self::from_uint_unchecked(U576::from_be_hex(hex))
    }

    /// Convert a `u64` into a [`FieldElement`].
    pub const fn from_u64(w: u64) -> Self {
        Self::from_uint_unchecked(U576::from_u64(w))
    }

    /// Decode [`FieldElement`] from [`U576`].
    ///
    /// Does *not* perform a check that the field element does not overflow the order.
    ///
    /// Used incorrectly this can lead to invalid results!
    #[cfg(target_pointer_width = "32")]
    pub(crate) const fn from_uint_unchecked(w: U576) -> Self {
        let words = w.to_words();

        Self([
            (words[0] as u64) | ((words[1] as u64) << 32),
            (words[2] as u64) | ((words[3] as u64) << 32),
            (words[4] as u64) | ((words[5] as u64) << 32),
            (words[6] as u64) | ((words[7] as u64) << 32),
            (words[8] as u64) | ((words[9] as u64) << 32),
            (words[10] as u64) | ((words[11] as u64) << 32),
            (words[12] as u64) | ((words[13] as u64) << 32),
            (words[14] as u64) | ((words[15] as u64) << 32),
            (words[16] as u64) | ((words[17] as u64) << 32),
        ])
    }

    /// Decode [`FieldElement`] from [`U576`].
    ///
    /// Does *not* perform a check that the field element does not overflow the order.
    ///
    /// Used incorrectly this can lead to invalid results!
    #[cfg(target_pointer_width = "64")]
    pub(crate) const fn from_uint_unchecked(w: U576) -> Self {
        Self(w.to_words())
    }

    /// Returns the big-endian encoding of this [`FieldElement`].
    pub fn to_bytes(self) -> FieldBytes {
        let mut ret = fiat_p521_to_bytes(&self.0);
        ret.reverse();
        GenericArray::clone_from_slice(&ret)
    }

    /// Determine if this [`FieldElement`] is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        Choice::from(self.0[0] as u8 & 1)
    }

    /// Determine if this [`FieldElement`] is even in the SEC1 sense: `self mod 2 == 0`.
    ///
    /// # Returns
    ///
    /// If even, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_even(&self) -> Choice {
        !self.is_odd()
    }

    /// Determine if this [`FieldElement`] is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Add elements.
    #[allow(dead_code)] // TODO(tarcieri): use this
    pub(crate) const fn add_loose(&self, rhs: &Self) -> LooseFieldElement {
        LooseFieldElement(fiat_p521_add(&self.0, &rhs.0))
    }

    /// Double element (add it to itself).
    #[allow(dead_code)] // TODO(tarcieri): use this
    #[must_use]
    pub(crate) const fn double_loose(&self) -> LooseFieldElement {
        Self::add_loose(self, self)
    }

    /// Subtract elements, returning a loose field element.
    #[allow(dead_code)] // TODO(tarcieri): use this
    pub(crate) const fn sub_loose(&self, rhs: &Self) -> LooseFieldElement {
        LooseFieldElement(fiat_p521_sub(&self.0, &rhs.0))
    }

    /// Negate element, returning a loose field element.
    #[allow(dead_code)] // TODO(tarcieri): use this
    pub(crate) const fn neg_loose(&self) -> LooseFieldElement {
        LooseFieldElement(fiat_p521_opp(&self.0))
    }

    /// Add two field elements.
    pub const fn add(&self, rhs: &Self) -> Self {
        Self(fiat_p521_carry_add(&self.0, &rhs.0))
    }

    /// Subtract field elements.
    pub const fn sub(&self, rhs: &Self) -> Self {
        Self(fiat_p521_carry_sub(&self.0, &rhs.0))
    }

    /// Negate element.
    pub const fn neg(&self) -> Self {
        Self(fiat_p521_carry_opp(&self.0))
    }

    /// Double element (add it to itself).
    #[must_use]
    pub const fn double(&self) -> Self {
        self.add(self)
    }

    /// Multiply elements.
    pub const fn mul(&self, rhs: &Self) -> Self {
        LooseFieldElement::mul(&self.relax(), &rhs.relax())
    }

    /// Square element.
    pub const fn square(&self) -> Self {
        self.relax().square()
    }

    /// Returns `self^exp`, where `exp` is a little-endian integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent.**
    ///
    /// If the exponent is fixed, this operation is effectively constant time.
    pub const fn pow_vartime(&self, exp: &[u64]) -> Self {
        let mut res = Self::ONE;
        let mut i = exp.len();

        while i > 0 {
            i -= 1;

            let mut j = 64;
            while j > 0 {
                j -= 1;
                res = res.square();

                if ((exp[i] >> j) & 1) == 1 {
                    res = Self::mul(&res, self);
                }
            }
        }

        res
    }

    /// Compute [`FieldElement`] inversion: `1 / self`.
    pub fn invert(&self) -> CtOption<Self> {
        todo!("`invert` not yet implemented")
    }

    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        todo!("`sqrt` not yet implemented")
    }

    /// Relax a tight field element into a loose one.
    pub(crate) const fn relax(&self) -> LooseFieldElement {
        LooseFieldElement(fiat_p521_relax(&self.0))
    }
}

impl AsRef<fiat_p521_tight_field_element> for FieldElement {
    fn as_ref(&self) -> &fiat_p521_tight_field_element {
        &self.0
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Eq for FieldElement {}
impl PartialEq for FieldElement {
    fn eq(&self, rhs: &Self) -> bool {
        self.0.ct_eq(&(rhs.0)).into()
    }
}

impl From<u32> for FieldElement {
    fn from(n: u32) -> FieldElement {
        Self::from_uint_unchecked(U576::from(n))
    }
}

impl From<u64> for FieldElement {
    fn from(n: u64) -> FieldElement {
        Self::from_uint_unchecked(U576::from(n))
    }
}

impl From<u128> for FieldElement {
    fn from(n: u128) -> FieldElement {
        Self::from_uint_unchecked(U576::from(n))
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut ret = Self::ZERO;

        for i in 0..ret.0.len() {
            ret.0[i] = u64::conditional_select(&a.0[i], &b.0[i], choice);
        }

        ret
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl DefaultIsZeroes for FieldElement {}

impl Field for FieldElement {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    fn random(mut rng: impl elliptic_curve::rand_core::RngCore) -> Self {
        // NOTE: can't use ScalarPrimitive::random due to CryptoRng bound
        let mut bytes = <FieldBytes>::default();

        loop {
            rng.fill_bytes(&mut bytes);
            if let Some(fe) = Self::from_bytes(&bytes).into() {
                return fe;
            }
        }
    }

    fn is_zero(&self) -> Choice {
        Self::ZERO.ct_eq(self)
    }

    #[must_use]
    fn square(&self) -> Self {
        self.square()
    }

    #[must_use]
    fn double(&self) -> Self {
        self.double()
    }

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }

    fn sqrt(&self) -> CtOption<Self> {
        self.sqrt()
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        ff::helpers::sqrt_ratio_generic(num, div)
    }
}

impl PrimeField for FieldElement {
    type Repr = FieldBytes;

    const MODULUS: &'static str = MODULUS_HEX;
    const NUM_BITS: u32 = 521;
    const CAPACITY: u32 = 520;
    const TWO_INV: Self = Self::ZERO; // TODO: unimplemented
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(3);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self = Self::from_hex("00000000000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
    const ROOT_OF_UNITY_INV: Self = Self::ZERO; // TODO: unimplemented
    const DELTA: Self = Self::from_u64(9);

    #[inline]
    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        Self::from_bytes(&bytes)
    }

    #[inline]
    fn to_repr(&self) -> FieldBytes {
        self.to_bytes()
    }

    #[inline]
    fn is_odd(&self) -> Choice {
        self.is_odd()
    }
}

//
// `core::ops` impls
//

impl Add for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn add(self, rhs: FieldElement) -> FieldElement {
        Self::add(&self, &rhs)
    }
}

impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn add(self, rhs: &FieldElement) -> FieldElement {
        Self::add(&self, rhs)
    }
}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    #[inline]
    fn add(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::add(self, rhs)
    }
}

impl AddAssign<FieldElement> for FieldElement {
    #[inline]
    fn add_assign(&mut self, other: FieldElement) {
        *self = *self + other;
    }
}

impl AddAssign<&FieldElement> for FieldElement {
    #[inline]
    fn add_assign(&mut self, other: &FieldElement) {
        *self = *self + other;
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn sub(self, rhs: FieldElement) -> FieldElement {
        Self::sub(&self, &rhs)
    }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn sub(self, rhs: &FieldElement) -> FieldElement {
        Self::sub(&self, rhs)
    }
}

impl Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    #[inline]
    fn sub(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::sub(self, rhs)
    }
}

impl SubAssign<FieldElement> for FieldElement {
    #[inline]
    fn sub_assign(&mut self, other: FieldElement) {
        *self = *self - other;
    }
}

impl SubAssign<&FieldElement> for FieldElement {
    #[inline]
    fn sub_assign(&mut self, other: &FieldElement) {
        *self = *self - other;
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn mul(self, rhs: FieldElement) -> FieldElement {
        self.relax().mul(&rhs.relax())
    }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn mul(self, rhs: &FieldElement) -> FieldElement {
        self.relax().mul(&rhs.relax())
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    #[inline]
    fn mul(self, rhs: &FieldElement) -> FieldElement {
        self.relax().mul(&rhs.relax())
    }
}

impl MulAssign<&FieldElement> for FieldElement {
    #[inline]
    fn mul_assign(&mut self, other: &FieldElement) {
        *self = *self * other;
    }
}

impl MulAssign for FieldElement {
    #[inline]
    fn mul_assign(&mut self, other: FieldElement) {
        *self = *self * other;
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn neg(self) -> FieldElement {
        Self::neg(&self)
    }
}

//
// `core::iter` trait impls
//

impl Sum for FieldElement {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(core::ops::Add::add).unwrap_or(Self::ZERO)
    }
}

impl<'a> Sum<&'a FieldElement> for FieldElement {
    fn sum<I: Iterator<Item = &'a FieldElement>>(iter: I) -> Self {
        iter.copied().sum()
    }
}

impl Product for FieldElement {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(core::ops::Mul::mul).unwrap_or(Self::ZERO)
    }
}

impl<'a> Product<&'a FieldElement> for FieldElement {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.copied().product()
    }
}
