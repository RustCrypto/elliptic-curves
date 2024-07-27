//! Field arithmetic modulo p = 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53
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

#[cfg_attr(target_pointer_width = "32", path = "field/bp384_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/bp384_64.rs")]
mod field_impl;

use self::field_impl::*;
use crate::{FieldBytes, U384};
use core::{
    fmt::{self, Debug},
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, Neg, SubAssign},
};
use elliptic_curve::ops::Invert;
use elliptic_curve::{
    bigint::{ArrayEncoding, Integer, Limb},
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, ConstantTimeLess, CtOption},
    Error, Result,
};

/// Constant representing the modulus serialized as hex.
const MODULUS_HEX: &str = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";

const MODULUS: U384 = U384::from_be_hex(MODULUS_HEX);

/// Element of the brainpoolP384's base field used for curve point coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(pub(super) U384);

impl FieldElement {
    /// Zero element.
    pub const ZERO: Self = Self(U384::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = Self::from_uint_unchecked(U384::ONE);

    /// Create a [`FieldElement`] from a canonical big-endian representation.
    pub fn from_bytes(field_bytes: &FieldBytes) -> CtOption<Self> {
        Self::from_uint(U384::from_be_byte_array(*field_bytes))
    }

    /// Decode [`FieldElement`] from a big endian byte slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let field_bytes = FieldBytes::try_from(slice).map_err(|_| Error)?;
        Self::from_bytes(&field_bytes).into_option().ok_or(Error)
    }

    /// Decode [`FieldElement`] from [`U384`] converting it into Montgomery form:
    ///
    /// ```text
    /// w * R^2 * R^-1 mod p = wR mod p
    /// ```
    pub fn from_uint(uint: U384) -> CtOption<Self> {
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
        Self::from_uint_unchecked(U384::from_be_hex(hex))
    }

    /// Convert a `u64` into a [`FieldElement`].
    pub const fn from_u64(w: u64) -> Self {
        Self::from_uint_unchecked(U384::from_u64(w))
    }

    /// Decode [`FieldElement`] from [`U384`] converting it into Montgomery form.
    ///
    /// Does *not* perform a check that the field element does not overflow the order.
    ///
    /// Used incorrectly this can lead to invalid results!
    pub(crate) const fn from_uint_unchecked(w: U384) -> Self {
        Self(U384::from_words(fiat_bp384_to_montgomery(w.as_words())))
    }

    /// Returns the big-endian encoding of this [`FieldElement`].
    pub fn to_bytes(self) -> FieldBytes {
        self.0.to_be_byte_array()
    }

    /// Translate [`FieldElement`] out of the Montgomery domain, returning a
    /// [`U384`] in canonical form.
    #[inline]
    pub const fn to_canonical(self) -> U384 {
        U384::from_words(fiat_bp384_from_montgomery(self.0.as_words()))
    }

    /// Determine if this [`FieldElement`] is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        self.to_canonical().is_odd()
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
    pub const fn add(&self, rhs: &Self) -> Self {
        Self(U384::from_words(fiat_bp384_add(
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
        Self(U384::from_words(fiat_bp384_sub(
            self.0.as_words(),
            rhs.0.as_words(),
        )))
    }

    /// Multiply elements.
    pub const fn multiply(&self, rhs: &Self) -> Self {
        Self(U384::from_words(fiat_bp384_mul(
            self.0.as_words(),
            rhs.0.as_words(),
        )))
    }

    /// Negate element.
    pub const fn neg(&self) -> Self {
        Self(U384::from_words(fiat_bp384_opp(self.0.as_words())))
    }

    /// Compute modular square.
    #[must_use]
    pub const fn square(&self) -> Self {
        Self(U384::from_words(fiat_bp384_square(self.0.as_words())))
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

    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Because p ≡ 3 mod 4 for brainpoolP384's base field modulus, sqrt can
        // be implemented with only one exponentiation via the computation of
        // self^((p + 1) // 4) (mod p).
        let sqrt = self.pow_vartime(&[
            0x61d1c004cc41fb15,
            0xeb34e9ca6407469c,
            0x04ac76865fedc448,
            0xc54bdc427b5515ad,
            0x03d75bdf94399077,
            0x232e47a0a8ce1b4a,
        ]);
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }

    /// Compute [`FieldElement`] inversion: `1 / self`.
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
            fiat_bp384_from_montgomery,
            fiat_bp384_mul,
            fiat_bp384_opp,
            fiat_bp384_divstep_precomp,
            fiat_bp384_divstep,
            fiat_bp384_msat,
            fiat_bp384_selectznz,
        );

        Self(U384::from_words(words))
    }
}

primeorder::impl_mont_field_element_arithmetic!(
    FieldElement,
    FieldBytes,
    U384,
    fiat_bp384_montgomery_domain_field_element,
    fiat_bp384_add,
    fiat_bp384_sub,
    fiat_bp384_mul,
    fiat_bp384_opp
);

impl Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement(0x{:X})", &self.0)
    }
}

impl PrimeField for FieldElement {
    type Repr = FieldBytes;

    const MODULUS: &'static str = MODULUS_HEX;
    const NUM_BITS: u32 = 384;
    const CAPACITY: u32 = 383;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(3);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self = Self::from_hex("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec52");
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

impl Invert for FieldElement {
    type Output = CtOption<Self>;

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }
}

#[cfg(test)]
mod tests {
    use super::FieldElement;
    use elliptic_curve::ff::PrimeField;
    use primeorder::{
        impl_field_identity_tests, impl_field_invert_tests, impl_field_sqrt_tests,
        impl_primefield_tests,
    };

    /// t = (modulus - 1) >> S
    /// 0x465c8f41519c369407aeb7bf287320ef8a97b884f6aa2b5a0958ed0cbfdb8891d669d394c80e8d38c3a380099883f629
    const T: [u64; 6] = [
        0xc3a380099883f629,
        0xd669d394c80e8d38,
        0x958ed0cbfdb8891,
        0x8a97b884f6aa2b5a,
        0x7aeb7bf287320ef,
        0x465c8f41519c3694,
    ];

    impl_field_identity_tests!(FieldElement);
    impl_field_invert_tests!(FieldElement);
    impl_field_sqrt_tests!(FieldElement);
    impl_primefield_tests!(FieldElement, T);
}
