//! brainpoolP256 scalar field elements.
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

#[cfg_attr(target_pointer_width = "32", path = "scalar/bp256_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/bp256_scalar_64.rs")]
mod scalar_impl;

use self::scalar_impl::*;
use crate::{FieldBytes, ORDER, ORDER_HEX, U256};
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

/// Element of brainpoolP256's scalar field.
#[derive(Clone, Copy, PartialOrd, Ord)]
pub struct Scalar(pub(super) U256);

impl Scalar {
    /// Zero element.
    pub const ZERO: Self = Self(U256::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = Self::from_uint_unchecked(U256::ONE);

    /// Create a [`Scalar`] from a canonical big-endian representation.
    pub fn from_bytes(field_bytes: &FieldBytes) -> CtOption<Self> {
        Self::from_uint(U256::from_be_byte_array(*field_bytes))
    }

    /// Decode [`Scalar`] from a big endian byte slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let field_bytes = FieldBytes::try_from(slice).map_err(|_| Error)?;
        Self::from_bytes(&field_bytes).into_option().ok_or(Error)
    }

    /// Decode [`Scalar`] from [`U256`] converting it into Montgomery form:
    ///
    /// ```text
    /// w * R^2 * R^-1 mod p = wR mod p
    /// ```
    pub fn from_uint(uint: U256) -> CtOption<Self> {
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
        Self::from_uint_unchecked(U256::from_be_hex(hex))
    }

    /// Convert a `u64` into a [`Scalar`].
    pub const fn from_u64(w: u64) -> Self {
        Self::from_uint_unchecked(U256::from_u64(w))
    }

    /// Decode [`Scalar`] from [`U256`] converting it into Montgomery form.
    ///
    /// Does *not* perform a check that the field element does not overflow the order.
    ///
    /// Used incorrectly this can lead to invalid results!
    pub(crate) const fn from_uint_unchecked(w: U256) -> Self {
        Self(U256::from_words(fiat_bp256_scalar_to_montgomery(
            w.as_words(),
        )))
    }

    /// Returns the big-endian encoding of this [`Scalar`].
    pub fn to_bytes(self) -> FieldBytes {
        self.0.to_be_byte_array()
    }

    /// Translate [`Scalar`] out of the Montgomery domain, returning a
    /// [`U256`] in canonical form.
    #[inline]
    pub const fn to_canonical(self) -> U256 {
        U256::from_words(fiat_bp256_scalar_from_montgomery(self.0.as_words()))
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
        Self(U256::from_words(fiat_bp256_scalar_add(
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
        Self(U256::from_words(fiat_bp256_scalar_sub(
            self.0.as_words(),
            rhs.0.as_words(),
        )))
    }

    /// Multiply elements.
    pub const fn multiply(&self, rhs: &Self) -> Self {
        Self(U256::from_words(fiat_bp256_scalar_mul(
            self.0.as_words(),
            rhs.0.as_words(),
        )))
    }

    /// Negate element.
    pub const fn neg(&self) -> Self {
        Self(U256::from_words(fiat_bp256_scalar_opp(self.0.as_words())))
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
        Self(U256::from_words(fiat_bp256_scalar_square(
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

    /// Returns the square root of self mod n, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Because n ≡ 3 mod 4 for brainpoolP256's scalar field modulus, sqrt
        // can be implemented with only one exponentiation via the computation
        // of self^((n + 1) // 4) (mod n).
        let sqrt = self.pow_vartime(&[
            0xe40783a0a5d215aa,
            0x630e5ea8ed5869bd,
            0x0f9982a42760e35c,
            0x2a7ed5f6e87baa6f,
        ]);
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
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
            256,
            U256::LIMBS,
            Limb,
            fiat_bp256_scalar_from_montgomery,
            fiat_bp256_scalar_mul,
            fiat_bp256_scalar_opp,
            fiat_bp256_scalar_divstep_precomp,
            fiat_bp256_scalar_divstep,
            fiat_bp256_scalar_msat,
            fiat_bp256_scalar_selectznz,
        );

        Self(U256::from_words(words))
    }
}

primeorder::impl_mont_field_element_arithmetic!(
    Scalar,
    FieldBytes,
    U256,
    fiat_bp256_scalar_montgomery_domain_field_element,
    fiat_bp256_scalar_add,
    fiat_bp256_scalar_sub,
    fiat_bp256_scalar_mul,
    fiat_bp256_scalar_opp
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
    type Uint = U256;

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
        const MODULUS_SHR1: U256 = ORDER.shr_vartime(1);
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
    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(3);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self =
        Self::from_hex("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6");
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
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

impl Reduce<U256> for Scalar {
    type Bytes = FieldBytes;

    fn reduce(w: U256) -> Self {
        let (r, underflow) = w.sbb(&ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U256::conditional_select(&w, &r, !underflow))
    }

    #[inline]
    fn reduce_bytes(bytes: &FieldBytes) -> Self {
        Self::reduce(U256::from_be_byte_array(*bytes))
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

impl From<Scalar> for U256 {
    fn from(scalar: Scalar) -> U256 {
        U256::from(&scalar)
    }
}

impl From<&Scalar> for U256 {
    fn from(scalar: &Scalar) -> U256 {
        scalar.to_canonical()
    }
}

impl TryFrom<U256> for Scalar {
    type Error = Error;

    fn try_from(w: U256) -> Result<Self> {
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
    /// 0x54fdabedd0f754de1f3305484ec1c6b8c61cbd51dab0d37bc80f07414ba42b53
    const T: [u64; 4] = [
        0xc80f07414ba42b53,
        0xc61cbd51dab0d37b,
        0x1f3305484ec1c6b8,
        0x54fdabedd0f754de,
    ];

    impl_field_identity_tests!(Scalar);
    impl_field_invert_tests!(Scalar);
    impl_field_sqrt_tests!(Scalar);
    impl_primefield_tests!(Scalar, T);
}
