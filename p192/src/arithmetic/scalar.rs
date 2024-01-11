//! secp192r1 scalar field elements.
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

#![allow(clippy::unusual_byte_groupings)]

#[cfg_attr(target_pointer_width = "32", path = "scalar/p192_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/p192_scalar_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::too_many_arguments,
    clippy::unnecessary_cast
)]
mod scalar_impl;

use self::scalar_impl::*;
use crate::{FieldBytes, FieldBytesEncoding, NistP192, ORDER_HEX, U192};
use core::{
    fmt::{self, Debug},
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, Neg, Shr, ShrAssign, SubAssign},
};
use elliptic_curve::{
    bigint::Limb,
    ff::PrimeField,
    ops::{Invert, Reduce},
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

/// Scalars are elements in the finite field modulo `n`.
///
/// # Trait impls
///
/// Much of the important functionality of scalars is provided by traits from
/// the [`ff`](https://docs.rs/ff/) crate, which is re-exported as
/// `p192::elliptic_curve::ff`:
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
pub struct Scalar(U192);

primeorder::impl_mont_field_element!(
    NistP192,
    Scalar,
    FieldBytes,
    U192,
    NistP192::ORDER,
    fiat_p192_scalar_montgomery_domain_field_element,
    fiat_p192_scalar_from_montgomery,
    fiat_p192_scalar_to_montgomery,
    fiat_p192_scalar_add,
    fiat_p192_scalar_sub,
    fiat_p192_scalar_mul,
    fiat_p192_scalar_opp,
    fiat_p192_scalar_square
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
            192,
            U192::LIMBS,
            Limb,
            fiat_p192_scalar_from_montgomery,
            fiat_p192_scalar_mul,
            fiat_p192_scalar_opp,
            fiat_p192_scalar_divstep_precomp,
            fiat_p192_scalar_divstep,
            fiat_p192_scalar_msat,
            fiat_p192_scalar_selectznz,
        );

        Self(U192::from_words(words))
    }

    /// Tonelli-Shank's algorithm for q mod 16 = 1
    /// <https://eprint.iacr.org/2012/685.pdf> (page 12, algorithm 5)
    #[allow(clippy::many_single_char_names)]
    fn sqrt(&self) -> CtOption<Self> {
        // w = self^((t - 1) // 2)
        // Note: `pow_vartime` is constant-time with respect to `self`
        let w = self.pow_vartime(&[0xb0a35e4d8da69141, 0xfffffffffccef7c1, 0x07ffffffffffffff]);

        let mut v = Self::S;
        let mut x = *self * w;
        let mut b = x * w;
        let mut z = Self::ROOT_OF_UNITY;

        for max_v in (1..=Self::S).rev() {
            let mut k = 1;
            let mut tmp = b.square();
            let mut j_less_than_v = Choice::from(1);

            for j in 2..max_v {
                let tmp_is_one = tmp.ct_eq(&Self::ONE);
                let squared = Self::conditional_select(&tmp, &z, tmp_is_one).square();
                tmp = Self::conditional_select(&squared, &tmp, tmp_is_one);
                let new_z = Self::conditional_select(&z, &squared, tmp_is_one);
                j_less_than_v &= !j.ct_eq(&v);
                k = u32::conditional_select(&j, &k, tmp_is_one);
                z = Self::conditional_select(&z, &new_z, j_less_than_v);
            }

            let result = x * z;
            x = Self::conditional_select(&result, &x, b.ct_eq(&Self::ONE));
            z = z.square();
            b *= z;
            v = k;
        }

        CtOption::new(x, x.square().ct_eq(self))
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
    type Uint = U192;

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
        const MODULUS_SHR1: U192 = NistP192::ORDER.shr_vartime(1);
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
    const NUM_BITS: u32 = 192;
    const CAPACITY: u32 = 191;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(3);
    const S: u32 = 4;
    const ROOT_OF_UNITY: Self = Self::from_hex("5c1fbd92d24b720fc3eee409e29f6b56b4db11947185a1bc");
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    const DELTA: Self = Self::from_u64(43046721);

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
    type ReprBits = fiat_p192_scalar_montgomery_domain_field_element;

    fn to_le_bits(&self) -> ScalarBits {
        self.to_canonical().to_words().into()
    }

    fn char_le_bits() -> ScalarBits {
        NistP192::ORDER.to_words().into()
    }
}

impl Reduce<U192> for Scalar {
    type Bytes = FieldBytes;

    fn reduce(w: U192) -> Self {
        let (r, underflow) = w.sbb(&NistP192::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U192::conditional_select(&w, &r, !underflow))
    }

    #[inline]
    fn reduce_bytes(bytes: &FieldBytes) -> Self {
        let w = <U192 as FieldBytesEncoding<NistP192>>::decode_field_bytes(bytes);
        Self::reduce(w)
    }
}

impl From<ScalarPrimitive<NistP192>> for Scalar {
    fn from(w: ScalarPrimitive<NistP192>) -> Self {
        Scalar::from(&w)
    }
}

impl From<&ScalarPrimitive<NistP192>> for Scalar {
    fn from(w: &ScalarPrimitive<NistP192>) -> Scalar {
        Scalar::from_uint_unchecked(*w.as_uint())
    }
}

impl From<Scalar> for ScalarPrimitive<NistP192> {
    fn from(scalar: Scalar) -> ScalarPrimitive<NistP192> {
        ScalarPrimitive::from(&scalar)
    }
}

impl From<&Scalar> for ScalarPrimitive<NistP192> {
    fn from(scalar: &Scalar) -> ScalarPrimitive<NistP192> {
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

impl From<Scalar> for U192 {
    fn from(scalar: Scalar) -> U192 {
        U192::from(&scalar)
    }
}

impl From<&Scalar> for U192 {
    fn from(scalar: &Scalar) -> U192 {
        scalar.to_canonical()
    }
}

impl TryFrom<U192> for Scalar {
    type Error = Error;

    fn try_from(w: U192) -> Result<Self> {
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

#[cfg(test)]
mod tests {
    use super::Scalar;
    use elliptic_curve::ff::PrimeField;
    use primeorder::{
        impl_field_identity_tests, impl_field_invert_tests, impl_field_sqrt_tests,
        impl_primefield_tests,
    };

    /// t = (modulus - 1) >> S
    /// 0xffffffffffffffffffffffff99def836146bc9b1b4d2283
    const T: [u64; 3] = [0x6146bc9b1b4d2283, 0xfffffffff99def83, 0x0fffffffffffffff];

    impl_field_identity_tests!(Scalar);
    impl_field_invert_tests!(Scalar);
    impl_field_sqrt_tests!(Scalar);
    impl_primefield_tests!(Scalar, T);
}
