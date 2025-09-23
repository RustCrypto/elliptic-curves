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

#[cfg_attr(target_pointer_width = "32", path = "scalar/p192_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/p192_scalar_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod scalar_impl;

use self::scalar_impl::*;
use crate::{FieldBytes, FieldBytesEncoding, NistP192, ORDER_HEX, U192};
use elliptic_curve::{
    Curve as _,
    bigint::Limb,
    ff::PrimeField,
    ops::Reduce,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption},
};

#[cfg(feature = "serde")]
use {
    elliptic_curve::ScalarValue,
    serdect::serde::{Deserialize, Serialize, de, ser},
};

#[cfg(doc)]
use core::ops::{Add, Mul, Neg, Sub};

primefield::monty_field_params! {
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: U192,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 3,
    doc: "Montgomery parameters for the NIST P-192 scalar modulus `n`."
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: U192,
    doc: "Element in the NIST P-192 scalar field modulo `n`."
}

primefield::monty_field_fiat_arithmetic!(
    Scalar,
    ScalarParams,
    U192,
    fiat_p192_scalar_non_montgomery_domain_field_element,
    fiat_p192_scalar_montgomery_domain_field_element,
    fiat_p192_scalar_from_montgomery,
    fiat_p192_scalar_to_montgomery,
    fiat_p192_scalar_add,
    fiat_p192_scalar_sub,
    fiat_p192_scalar_mul,
    fiat_p192_scalar_opp,
    fiat_p192_scalar_square,
    fiat_p192_scalar_divstep_precomp,
    fiat_p192_scalar_divstep,
    fiat_p192_scalar_msat,
    fiat_p192_scalar_selectznz
);

elliptic_curve::scalar_impls!(NistP192, Scalar);

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U192;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U192 = NistP192::ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl Reduce<U192> for Scalar {
    fn reduce(w: &U192) -> Self {
        let (r, underflow) = w.borrowing_sub(&NistP192::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U192::conditional_select(w, &r, !underflow))
    }
}

impl Reduce<FieldBytes> for Scalar {
    #[inline]
    fn reduce(bytes: &FieldBytes) -> Self {
        let w = <U192 as FieldBytesEncoding<NistP192>>::decode_field_bytes(bytes);
        Self::reduce(&w)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        ScalarValue::from(self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(ScalarValue::deserialize(deserializer)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, U192};
    primefield::test_primefield!(Scalar, U192);
}
