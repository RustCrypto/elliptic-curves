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

#[cfg_attr(target_pointer_width = "32", path = "scalar/p224_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/p224_scalar_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod scalar_impl;

use self::scalar_impl::*;
use crate::{FieldBytes, FieldBytesEncoding, NistP224, ORDER_HEX, Uint};
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
    uint: Uint,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 2,
    doc: "Montgomery parameters for the NIST P-224 scalar modulus `n`."
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: Uint,
    doc: "Element in the NIST P-224 scalar field modulo `n`."
}

primefield::fiat_monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: Uint,
    non_mont: fiat_p224_scalar_non_montgomery_domain_field_element,
    mont: fiat_p224_scalar_montgomery_domain_field_element,
    from_mont: fiat_p224_scalar_from_montgomery,
    to_mont: fiat_p224_scalar_to_montgomery,
    add: fiat_p224_scalar_add,
    sub: fiat_p224_scalar_sub,
    mul: fiat_p224_scalar_mul,
    neg: fiat_p224_scalar_opp,
    square: fiat_p224_scalar_square,
    divstep_precomp: fiat_p224_scalar_divstep_precomp,
    divstep: fiat_p224_scalar_divstep,
    msat: fiat_p224_scalar_msat,
    selectnz: fiat_p224_scalar_selectznz
}

elliptic_curve::scalar_impls!(NistP224, Scalar);

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
        const MODULUS_SHR1: Uint = NistP224::ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl Reduce<Uint> for Scalar {
    fn reduce(w: &Uint) -> Self {
        let (r, underflow) = w.borrowing_sub(&NistP224::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(Uint::conditional_select(w, &r, !underflow))
    }
}

impl Reduce<FieldBytes> for Scalar {
    #[inline]
    fn reduce(bytes: &FieldBytes) -> Self {
        let w = <Uint as FieldBytesEncoding<NistP224>>::decode_field_bytes(bytes);
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
    use super::{Scalar, Uint};
    use super::{
        ScalarParams, fiat_p224_scalar_montgomery_domain_field_element, fiat_p224_scalar_msat,
        fiat_p224_scalar_non_montgomery_domain_field_element, fiat_p224_scalar_to_montgomery,
    };

    primefield::test_primefield!(Scalar, Uint);
    primefield::test_fiat_monty_field_arithmetic!(
        name: Scalar,
        params: ScalarParams,
        uint: Uint,
        non_mont: fiat_p224_scalar_non_montgomery_domain_field_element,
        mont: fiat_p224_scalar_montgomery_domain_field_element,
        to_mont: fiat_p224_scalar_to_montgomery,
        msat: fiat_p224_scalar_msat
    );
}
