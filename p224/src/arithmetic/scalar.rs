//! secp224r1 scalar field elements.
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

#[cfg_attr(target_pointer_width = "32", path = "scalar/p224_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/p224_scalar_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::too_many_arguments,
    clippy::unnecessary_cast
)]
mod scalar_impl;

use self::scalar_impl::*;
use crate::{FieldBytes, FieldBytesEncoding, NistP224, ORDER_HEX, Uint};
use elliptic_curve::{
    Curve as _, Error, Result,
    bigint::Limb,
    ff::PrimeField,
    ops::Reduce,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption},
};

#[cfg(feature = "bits")]
use {
    crate::ScalarBits,
    elliptic_curve::{bigint::Word, group::ff::PrimeFieldBits},
};

#[cfg(feature = "serde")]
use {
    elliptic_curve::ScalarPrimitive,
    serdect::serde::{Deserialize, Serialize, de, ser},
};

#[cfg(doc)]
use core::ops::{Add, Mul, Neg, Sub};

/// Scalars are elements in the finite field modulo `n`.
///
/// # Trait impls
///
/// Much of the important functionality of scalars is provided by traits from
/// the [`ff`](https://docs.rs/ff/) crate, which is re-exported as
/// `p224::elliptic_curve::ff`:
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
///
/// # Warning: `sqrt` unimplemented!
///
/// `Scalar::sqrt` has not been implemented and will panic if invoked!
///
/// See [RustCrypto/elliptic-curves#847] for more info.
///
/// [RustCrypto/elliptic-curves#847]: https://github.com/RustCrypto/elliptic-curves/issues/847
#[derive(Clone, Copy, PartialOrd, Ord)]
pub struct Scalar(Uint);

primefield::field_element_type!(
    Scalar,
    FieldBytes,
    Uint,
    NistP224::ORDER,
    FieldBytesEncoding::<NistP224>::decode_field_bytes,
    FieldBytesEncoding::<NistP224>::encode_field_bytes
);

primefield::fiat_field_arithmetic!(
    Scalar,
    FieldBytes,
    Uint,
    fiat_p224_scalar_non_montgomery_domain_field_element,
    fiat_p224_scalar_montgomery_domain_field_element,
    fiat_p224_scalar_from_montgomery,
    fiat_p224_scalar_to_montgomery,
    fiat_p224_scalar_add,
    fiat_p224_scalar_sub,
    fiat_p224_scalar_mul,
    fiat_p224_scalar_opp,
    fiat_p224_scalar_square,
    fiat_p224_scalar_divstep_precomp,
    fiat_p224_scalar_divstep,
    fiat_p224_scalar_msat,
    fiat_p224_scalar_selectznz
);

elliptic_curve::scalar_impls!(NistP224, Scalar);

impl Scalar {
    /// Atkin algorithm for q mod 8 = 5
    /// <https://eips.ethereum.org/assets/eip-3068/2012-685_Square_Root_Even_Ext.pdf>
    /// (page 10, algorithm 3)
    pub fn sqrt(&self) -> CtOption<Self> {
        let w = &[
            0xc27ba528ab8b8547,
            0xffffe2d45c171e07,
            0xffffffffffffffff,
            0x1fffffff,
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
}

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = Uint;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: Uint = NistP224::ORDER.shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const MODULUS: &'static str = ORDER_HEX;
    const CAPACITY: u32 = 223;
    const NUM_BITS: u32 = 224;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(2);
    const S: u32 = 2;
    #[cfg(target_pointer_width = "32")]
    const ROOT_OF_UNITY: Self =
        Self::from_hex("317fd4f4d5947c88975e7ca95d8c1164ceed46e611c9e5bafaa1aa3d");
    #[cfg(target_pointer_width = "64")]
    const ROOT_OF_UNITY: Self =
        Self::from_hex("00000000317fd4f4d5947c88975e7ca95d8c1164ceed46e611c9e5bafaa1aa3d");
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

#[cfg(feature = "bits")]
impl PrimeFieldBits for Scalar {
    type ReprBits = [Word; Uint::LIMBS];

    fn to_le_bits(&self) -> ScalarBits {
        self.to_canonical().to_words().into()
    }

    fn char_le_bits() -> ScalarBits {
        NistP224::ORDER.to_words().into()
    }
}

impl Reduce<Uint> for Scalar {
    type Bytes = FieldBytes;

    fn reduce(w: Uint) -> Self {
        let (r, underflow) = w.borrowing_sub(&NistP224::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(Uint::conditional_select(&w, &r, !underflow))
    }

    #[inline]
    fn reduce_bytes(bytes: &FieldBytes) -> Self {
        let w = <Uint as FieldBytesEncoding<NistP224>>::decode_field_bytes(bytes);
        Self::reduce(w)
    }
}

impl TryFrom<Uint> for Scalar {
    type Error = Error;

    fn try_from(w: Uint) -> Result<Self> {
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
    use super::{Scalar, Uint};
    primefield::test_primefield!(Scalar, Uint);
}
