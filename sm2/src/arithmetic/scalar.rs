//! SM2 scalar field elements.
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

#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::identity_op,
    clippy::too_many_arguments,
    clippy::unnecessary_cast
)]

#[cfg_attr(target_pointer_width = "32", path = "scalar/sm2_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/sm2_scalar_64.rs")]
mod scalar_impl;

use self::scalar_impl::*;
use crate::{FieldBytes, FieldBytesEncoding, SecretKey, Sm2, ORDER_HEX, U256};
use core::{
    fmt::{self, Debug},
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, Neg, Shr, ShrAssign, SubAssign},
};
use elliptic_curve::{
    bigint::Limb,
    ff::PrimeField,
    ops::Reduce,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption},
    Curve as _, Error, Result, ScalarPrimitive,
};

#[cfg(feature = "bits")]
use {crate::ScalarBits, elliptic_curve::group::ff::PrimeFieldBits};

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

#[cfg(doc)]
use core::ops::{Add, Mul, Sub};
use elliptic_curve::ops::Invert;

/// Scalars are elements in the finite field modulo `n`.
///
/// # Trait impls
///
/// Much of the important functionality of scalars is provided by traits from
/// the [`ff`](https://docs.rs/ff/) crate, which is re-exported as
/// `sm2::elliptic_curve::ff`:
///
/// - [`Field`](https://docs.rs/ff/latest/ff/trait.Field.html) -
///   represents elements of finite fields and provides:
///   - [`Field::random`](https://docs.rs/ff/latest/ff/trait.Field.html#tymethod.random) -
///     generate a random scalar
///   - `double`, `square`, and `invert` operations
///   - Bounds for [`Add`], [`Sub`], [`Mul`], and [`Neg`] (as well as `*Assign` equivalents)
///   - Bounds for [`ConditionallySelectable`] from the `subtle` crate
/// - [`PrimeField`](https://docs.rs/ff/latest/ff/trait.PrimeField.html) -
///   represents elements of prime fields and provides:
///   - `from_repr`/`to_repr` for converting field elements from/to big integers.
///   - `multiplicative_generator` and `root_of_unity` constants.
/// - [`PrimeFieldBits`](https://docs.rs/ff/latest/ff/trait.PrimeFieldBits.html) -
///   operations over field elements represented as bits (requires `bits` feature)
///
/// Please see the documentation for the relevant traits for more information.
#[derive(Clone, Copy, PartialOrd, Ord)]
pub struct Scalar(U256);

primeorder::impl_mont_field_element!(
    Sm2,
    Scalar,
    FieldBytes,
    U256,
    Sm2::ORDER,
    fiat_sm2_scalar_montgomery_domain_field_element,
    fiat_sm2_scalar_from_montgomery,
    fiat_sm2_scalar_to_montgomery,
    fiat_sm2_scalar_add,
    fiat_sm2_scalar_sub,
    fiat_sm2_scalar_mul,
    fiat_sm2_scalar_opp,
    fiat_sm2_scalar_square
);

impl Scalar {
    /// Compute [`Scalar`] inversion: `1 / self`.
    pub fn invert(&self) -> CtOption<Self> {
        CtOption::new(self.invert_unchecked(), !self.is_zero())
    }

    /// Compute [`Scalar`] inversion: `1 / self`.
    ///
    /// Does not check that self is non-zero.
    const fn invert_unchecked(&self) -> Self {
        let words = primeorder::impl_bernstein_yang_invert!(
            self.0.as_words(),
            Self::ONE.0.to_words(),
            256,
            U256::LIMBS,
            Limb,
            fiat_sm2_scalar_from_montgomery,
            fiat_sm2_scalar_mul,
            fiat_sm2_scalar_opp,
            fiat_sm2_scalar_divstep_precomp,
            fiat_sm2_scalar_divstep,
            fiat_sm2_scalar_msat,
            fiat_sm2_scalar_selectznz,
        );

        Self(U256::from_words(words))
    }

    /// Returns the square root of self mod n, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Because n ≡ 3 mod 4 for SM2's scalar field modulus, sqrt can be done with only one
        // exponentiation via the computation of self^((n + 1) // 4) (mod n).
        let sqrt = self.pow_vartime(&[
            0xd4eefd024e755049,
            0xdc80f7dac871814a,
            0xffffffffffffffff,
            0x3fffffffbfffffff,
        ]);
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }

    /// Right shifts the scalar.
    ///
    /// Note: not constant-time with respect to the `shift` parameter.
    pub const fn shr_vartime(&self, shift: u32) -> Scalar {
        Self(self.0.wrapping_shr_vartime(shift))
    }
}

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

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U256 = Sm2::ORDER.shr_vartime(1);
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
        Self::from_hex("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54122");
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

#[cfg(feature = "bits")]
impl PrimeFieldBits for Scalar {
    type ReprBits = fiat_sm2_scalar_montgomery_domain_field_element;

    fn to_le_bits(&self) -> ScalarBits {
        self.to_canonical().to_words().into()
    }

    fn char_le_bits() -> ScalarBits {
        Sm2::ORDER.to_words().into()
    }
}

impl Reduce<U256> for Scalar {
    type Bytes = FieldBytes;

    fn reduce(w: U256) -> Self {
        let (r, underflow) = w.sbb(&Sm2::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U256::conditional_select(&w, &r, !underflow))
    }

    #[inline]
    fn reduce_bytes(bytes: &FieldBytes) -> Self {
        let w = <U256 as FieldBytesEncoding<Sm2>>::decode_field_bytes(bytes);
        Self::reduce(w)
    }
}

impl From<ScalarPrimitive<Sm2>> for Scalar {
    fn from(w: ScalarPrimitive<Sm2>) -> Self {
        Scalar::from(&w)
    }
}

impl From<&ScalarPrimitive<Sm2>> for Scalar {
    fn from(w: &ScalarPrimitive<Sm2>) -> Scalar {
        Scalar::from_uint_unchecked(*w.as_uint())
    }
}

impl From<Scalar> for ScalarPrimitive<Sm2> {
    fn from(scalar: Scalar) -> ScalarPrimitive<Sm2> {
        ScalarPrimitive::from(&scalar)
    }
}

impl From<&Scalar> for ScalarPrimitive<Sm2> {
    fn from(scalar: &Scalar) -> ScalarPrimitive<Sm2> {
        ScalarPrimitive::new(scalar.into()).unwrap()
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

impl From<&SecretKey> for Scalar {
    fn from(secret_key: &SecretKey) -> Scalar {
        *secret_key.to_nonzero_scalar()
    }
}

impl TryFrom<U256> for Scalar {
    type Error = Error;

    fn try_from(w: U256) -> Result<Self> {
        Option::from(Self::from_uint(w)).ok_or(Error)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        ScalarPrimitive::from(self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(ScalarPrimitive::deserialize(deserializer)?.into())
    }
}

impl Invert for Scalar {
    type Output = CtOption<Self>;

    fn invert(&self) -> CtOption<Self> {
        self.invert()
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
    /// 0x7fffffff7fffffffffffffffffffffffb901efb590e30295a9ddfa049ceaa091
    const T: [u64; 4] = [
        0xa9ddfa049ceaa091,
        0xb901efb590e30295,
        0xffffffffffffffff,
        0x7fffffff7fffffff,
    ];

    impl_field_identity_tests!(Scalar);
    impl_field_invert_tests!(Scalar);
    impl_field_sqrt_tests!(Scalar);
    impl_primefield_tests!(Scalar, T);
}
