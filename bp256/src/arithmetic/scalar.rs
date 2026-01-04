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
#[allow(
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod scalar_impl;

use self::scalar_impl::*;
use crate::{BrainpoolP256r1, BrainpoolP256t1, FieldBytes, ORDER, ORDER_HEX, U256};
use elliptic_curve::{
    bigint::{ArrayEncoding, Limb},
    ff::PrimeField,
    ops::Reduce,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption},
};

#[cfg(doc)]
use core::ops::{Add, Mul, Sub};

primefield::monty_field_params! {
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: U256,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 3,
    doc: "Montgomery parameters for brainpoolP256's scalar modulus"
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: U256,
    doc: "Element in the brainpoolP256 scalar field modulo n"
}

primefield::fiat_monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U256,
    non_mont: fiat_bp256_scalar_non_montgomery_domain_field_element,
    mont: fiat_bp256_scalar_montgomery_domain_field_element,
    from_mont: fiat_bp256_scalar_from_montgomery,
    to_mont: fiat_bp256_scalar_to_montgomery,
    add: fiat_bp256_scalar_add,
    sub: fiat_bp256_scalar_sub,
    mul: fiat_bp256_scalar_mul,
    neg: fiat_bp256_scalar_opp,
    square: fiat_bp256_scalar_square,
    divstep_precomp: fiat_bp256_scalar_divstep_precomp,
    divstep: fiat_bp256_scalar_divstep,
    msat: fiat_bp256_scalar_msat,
    selectnz: fiat_bp256_scalar_selectznz
}

elliptic_curve::scalar_impls!(BrainpoolP256r1, Scalar);
elliptic_curve::scalar_impls!(BrainpoolP256t1, Scalar);

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
        const MODULUS_SHR1: U256 = ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl Reduce<U256> for Scalar {
    fn reduce(w: &U256) -> Self {
        let (r, underflow) = w.borrowing_sub(&ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U256::conditional_select(w, &r, !underflow))
    }
}

impl Reduce<FieldBytes> for Scalar {
    #[inline]
    fn reduce(bytes: &FieldBytes) -> Self {
        Self::reduce(&U256::from_be_byte_array(*bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, U256};
    primefield::test_primefield!(Scalar, U256);
}
