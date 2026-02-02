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

use crate::{ORDER_HEX, Sm2, U256};
use elliptic_curve::{
    Curve as _,
    bigint::cpubits,
    ff::PrimeField,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, CtOption},
};

// Default backend: fiat-crypto
cpubits! {
    32 => {
        #[cfg(not(sm2_backend = "bignum"))]
        use fiat_crypto::sm2_scalar_32::*;
    }
    64 => {
        #[cfg(not(sm2_backend = "bignum"))]
        use fiat_crypto::sm2_scalar_64::*;
    }
}

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
    uint: U256,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 3,
    doc: "Montgomery parameters for the SM2 scalar modulus `n`."
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: U256,
    doc: "Element in the SM2 scalar field modulo `n`."
}

#[cfg(sm2_backend = "bignum")]
primefield::monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U256
}

#[cfg(not(sm2_backend = "bignum"))]
primefield::fiat_monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U256,
    non_mont: fiat_sm2_scalar_non_montgomery_domain_field_element,
    mont: fiat_sm2_scalar_montgomery_domain_field_element,
    from_mont: fiat_sm2_scalar_from_montgomery,
    to_mont: fiat_sm2_scalar_to_montgomery,
    add: fiat_sm2_scalar_add,
    sub: fiat_sm2_scalar_sub,
    mul: fiat_sm2_scalar_mul,
    neg: fiat_sm2_scalar_opp,
    square: fiat_sm2_scalar_square,
    divstep_precomp: fiat_sm2_scalar_divstep_precomp,
    divstep: fiat_sm2_scalar_divstep,
    msat: fiat_sm2_scalar_msat,
    selectnz: fiat_sm2_scalar_selectznz
}

primefield::monty_field_reduce! {
    name: Scalar,
    params: ScalarParams,
    uint: U256,
}

elliptic_curve::scalar_impls!(Sm2, Scalar);

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
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
        const MODULUS_SHR1: U256 = Sm2::ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
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
    use super::{Scalar, U256};
    #[cfg(not(sm2_backend = "bignum"))]
    use super::{
        ScalarParams, fiat_sm2_scalar_montgomery_domain_field_element, fiat_sm2_scalar_msat,
        fiat_sm2_scalar_non_montgomery_domain_field_element, fiat_sm2_scalar_to_montgomery,
    };

    primefield::test_primefield!(Scalar, U256);
    #[cfg(not(sm2_backend = "bignum"))]
    primefield::test_fiat_monty_field_arithmetic!(
        name: Scalar,
        params: ScalarParams,
        uint: U256,
        non_mont: fiat_sm2_scalar_non_montgomery_domain_field_element,
        mont: fiat_sm2_scalar_montgomery_domain_field_element,
        to_mont: fiat_sm2_scalar_to_montgomery,
        msat: fiat_sm2_scalar_msat
    );
}
