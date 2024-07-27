//! brainpoolP384 scalar field elements.
//!
//! Arithmetic implementations have been synthesized using fiat-crypto.
//!
//! # License
//!
//! Copyright (c) 2015-2020 the fiat-crypto authors
//!
//! fiat-crypto is distributed under the terms of the MIT License, the
//! Apache License (Version 2.0), and the BSD 1-Clause License;
//! users may pick which license to apply.

#[cfg_attr(target_pointer_width = "32", path = "scalar/bp384_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/bp384_scalar_64.rs")]
mod scalar_impl;

use self::scalar_impl::*;
use crate::{FieldBytes, ORDER, ORDER_HEX, U384};
use core::{
    fmt::{self, Debug},
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, Neg, Shr, ShrAssign, SubAssign},
};
use elliptic_curve::{
    bigint::{ArrayEncoding, Integer, Limb},
    ff::PrimeField,
    ops::{Invert, Reduce},
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{
        Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
        CtOption,
    },
    Error, Result,
};

#[cfg(doc)]
use core::ops::{Add, Mul, Sub};

/// Element of the brainpoolP384's scalar field.
#[derive(Clone, Copy, PartialOrd, Ord)]
pub struct Scalar(pub(super) U384);

impl Scalar {
    /// Zero element.
    pub const ZERO: Self = Self(U384::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = Self::from_uint_unchecked(U384::ONE);

    /// Create a [`Scalar`] from a canonical big-endian representation.
    pub fn from_bytes(field_bytes: &FieldBytes) -> CtOption<Self> {
        Self::from_uint(U384::from_be_byte_array(*field_bytes))
    }

    /// Decode [`Scalar`] from a big endian byte slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let field_bytes = FieldBytes::try_from(slice).map_err(|_| Error)?;
        Self::from_bytes(&field_bytes).into_option().ok_or(Error)
    }

    /// Decode [`Scalar`] from [`U384`] converting it into Montgomery form:
    ///
    /// ```text
    /// w * R^2 * R^-1 mod p = wR mod p
    /// ```
    pub fn from_uint(uint: U384) -> CtOption<Self> {
        let is_some = uint.ct_lt(&ORDER);
        CtOption::new(Self::from_uint_unchecked(uint), is_some)
    }

    /// Parse a [`Scalar`] from big endian hex-encoded bytes.
    ///
    /// Does *not* perform a check that the field element does not overflow the order.
    ///
    /// This method is primarily intended for defining internal constants.
    #[allow(dead_code)]
    pub(crate) const fn from_hex(hex: &str) -> Self {
        Self::from_uint_unchecked(U384::from_be_hex(hex))
    }

    /// Convert a `u64` into a [`Scalar`].
    pub const fn from_u64(w: u64) -> Self {
        Self::from_uint_unchecked(U384::from_u64(w))
    }

    /// Decode [`Scalar`] from [`U384`] converting it into Montgomery form.
    ///
    /// Does *not* perform a check that the field element does not overflow the order.
    ///
    /// Used incorrectly this can lead to invalid results!
    pub(crate) const fn from_uint_unchecked(w: U384) -> Self {
        Self(U384::from_words(fiat_bp384_scalar_to_montgomery(
            w.as_words(),
        )))
    }

    /// Returns the big-endian encoding of this [`Scalar`].
    pub fn to_bytes(self) -> FieldBytes {
        self.0.to_be_byte_array()
    }

    /// Translate [`Scalar`] out of the Montgomery domain, returning a
    /// [`U384`] in canonical form.
    #[inline]
    pub const fn to_canonical(self) -> U384 {
        U384::from_words(fiat_bp384_scalar_from_montgomery(self.0.as_words()))
    }

    /// Determine if this [`Scalar`] is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        self.to_canonical().is_odd()
    }

    /// Determine if this [`Scalar`] is even in the SEC1 sense: `self mod 2 == 0`.
    ///
    /// # Returns
    ///
    /// If even, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_even(&self) -> Choice {
        !self.is_odd()
    }

    /// Determine if this [`Scalar`] is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Add elements.
    pub const fn add(&self, rhs: &Self) -> Self {
        Self(U384::from_words(fiat_bp384_scalar_add(
            self.0.as_words(),
            rhs.0.as_words(),
        )))
    }

    /// Double element (add it to itself).
    #[must_use]
    pub const fn double(&self) -> Self {
        self.add(self)
    }

    /// Subtract elements.
    pub const fn sub(&self, rhs: &Self) -> Self {
        Self(U384::from_words(fiat_bp384_scalar_sub(
            self.0.as_words(),
            rhs.0.as_words(),
        )))
    }

    /// Multiply elements.
    pub const fn multiply(&self, rhs: &Self) -> Self {
        Self(U384::from_words(fiat_bp384_scalar_mul(
            self.0.as_words(),
            rhs.0.as_words(),
        )))
    }

    /// Negate element.
    pub const fn neg(&self) -> Self {
        Self(U384::from_words(fiat_bp384_scalar_opp(self.0.as_words())))
    }

    /// Right shifts the scalar.
    ///
    /// Note: not constant-time with respect to the `shift` parameter.
    pub const fn shr_vartime(&self, shift: u32) -> Scalar {
        Self(self.0.wrapping_shr_vartime(shift))
    }

    /// Compute modular square.
    #[must_use]
    pub const fn square(&self) -> Self {
        Self(U384::from_words(fiat_bp384_scalar_square(
            self.0.as_words(),
        )))
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
                    res = res.multiply(self);
                }
            }
        }

        res
    }

    /// Atkin algorithm for q mod 8 = 5
    /// <https://eips.ethereum.org/assets/eip-3068/2012-685_Square_Root_Even_Ext.pdf>
    /// (page 10, algorithm 3)
    pub fn sqrt(&self) -> CtOption<Self> {
        let w = &[
            0x077106405d208cac,
            0xf9e756d5ed6ff862,
            0x63e2cdcd958084b4,
            0xe2a5ee213daa8ad6,
            0x01ebadefca1cc83b,
            0x119723d054670da5,
        ];
        let t = Self::from_u64(2).pow_vartime(w);
        let a1 = self.pow_vartime(w);
        let a0 = (a1.square() * self).square();
        let b = t * a1;
        let ab = self * &b;
        let i = Self::from_u64(2) * ab * b;
        let x = ab * (i - Self::ONE);
        CtOption::new(x, !a0.ct_eq(&-Self::ONE))
    }

    /// Compute [`Scalar`] inversion: `1 / self`.
    pub fn invert(&self) -> CtOption<Self> {
        CtOption::new(self.invert_unchecked(), !self.is_zero())
    }

    /// Returns the multiplicative inverse of self.
    ///
    /// Does not check that self is non-zero.
    const fn invert_unchecked(&self) -> Self {
        let words = primeorder::impl_bernstein_yang_invert!(
            self.0.as_words(),
            Self::ONE.0.to_words(),
            384,
            U384::LIMBS,
            Limb,
            fiat_bp384_scalar_from_montgomery,
            fiat_bp384_scalar_mul,
            fiat_bp384_scalar_opp,
            fiat_bp384_scalar_divstep_precomp,
            fiat_bp384_scalar_divstep,
            fiat_bp384_scalar_msat,
            fiat_bp384_scalar_selectznz,
        );

        Self(U384::from_words(words))
    }
}

primeorder::impl_mont_field_element_arithmetic!(
    Scalar,
    FieldBytes,
    U384,
    fiat_bp384_scalar_montgomery_domain_field_element,
    fiat_bp384_scalar_add,
    fiat_bp384_scalar_sub,
    fiat_bp384_scalar_mul,
    fiat_bp384_scalar_opp
);

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scalar(0x{:X})", &self.0)
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U384;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl Invert for Scalar {
    type Output = CtOption<Self>;

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U384 = ORDER.shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl Shr<usize> for Scalar {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        self.shr_vartime(rhs as u32)
    }
}

impl Shr<usize> for &Scalar {
    type Output = Scalar;

    fn shr(self, rhs: usize) -> Self::Output {
        self.shr_vartime(rhs as u32)
    }
}

impl ShrAssign<usize> for Scalar {
    fn shr_assign(&mut self, rhs: usize) {
        *self = *self >> rhs;
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const MODULUS: &'static str = ORDER_HEX;
    const NUM_BITS: u32 = 384;
    const CAPACITY: u32 = 383;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(2);
    const S: u32 = 2;
    const ROOT_OF_UNITY: Self = Self::from_hex("76cdc6369fb54dde55a851fce47cc5f830bb074c85684b3ee476be128dc50cfa8602aeecf53a1982fcf3b95f8d4258ff");
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    const DELTA: Self = Self::from_u64(16);

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

impl Reduce<U384> for Scalar {
    type Bytes = FieldBytes;

    fn reduce(w: U384) -> Self {
        let (r, underflow) = w.sbb(&ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U384::conditional_select(&w, &r, !underflow))
    }

    #[inline]
    fn reduce_bytes(bytes: &FieldBytes) -> Self {
        Self::reduce(U384::from_be_byte_array(*bytes))
    }
}

impl From<Scalar> for FieldBytes {
    fn from(scalar: Scalar) -> Self {
        scalar.to_repr()
    }
}

impl From<&Scalar> for FieldBytes {
    fn from(scalar: &Scalar) -> Self {
        scalar.to_repr()
    }
}

impl From<Scalar> for U384 {
    fn from(scalar: Scalar) -> U384 {
        U384::from(&scalar)
    }
}

impl From<&Scalar> for U384 {
    fn from(scalar: &Scalar) -> U384 {
        scalar.to_canonical()
    }
}

impl TryFrom<U384> for Scalar {
    type Error = Error;

    fn try_from(w: U384) -> Result<Self> {
        Option::from(Self::from_uint(w)).ok_or(Error)
    }
}

#[cfg(test)]
mod tests {
    use super::Scalar;
    use elliptic_curve::ff::PrimeField;
    use primeorder::{
        impl_field_identity_tests, impl_field_invert_tests, impl_field_sqrt_tests,
        impl_primefield_tests,
    };

    /// t = (modulus - 1) >> S
    /// 0x232e47a0a8ce1b4a03d75bdf94399077c54bdc427b5515acc7c59b9b2b010969f3ceadabdadff0c40ee20c80ba411959
    const T: [u64; 6] = [
        0x0ee20c80ba411959,
        0xf3ceadabdadff0c4,
        0xc7c59b9b2b010969,
        0xc54bdc427b5515ac,
        0x03d75bdf94399077,
        0x232e47a0a8ce1b4a,
    ];

    impl_field_identity_tests!(Scalar);
    impl_field_invert_tests!(Scalar);
    impl_field_sqrt_tests!(Scalar);
    impl_primefield_tests!(Scalar, T);
}
