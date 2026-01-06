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

#[cfg(not(bp384_backend = "bignum"))]
#[cfg_attr(target_pointer_width = "32", path = "scalar/bp384_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/bp384_scalar_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod scalar_impl;

use crate::{BrainpoolP384r1, BrainpoolP384t1, ORDER, ORDER_HEX, U384};
use elliptic_curve::{
    ff::PrimeField,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, CtOption},
};

#[cfg(not(bp384_backend = "bignum"))]
use self::scalar_impl::*;

#[cfg(doc)]
use core::ops::{Add, Mul, Sub};

primefield::monty_field_params! {
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: U384,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 2,
    doc: "Montgomery parameters for brainpoolP384's scalar modulus"
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: U384,
    doc: "Element in the brainpoolP384 scalar field modulo n"
}

#[cfg(bp384_backend = "bignum")]
primefield::monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U384
}

#[cfg(not(bp384_backend = "bignum"))]
primefield::fiat_monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U384,
    non_mont: fiat_bp384_scalar_non_montgomery_domain_field_element,
    mont: fiat_bp384_scalar_montgomery_domain_field_element,
    from_mont: fiat_bp384_scalar_from_montgomery,
    to_mont: fiat_bp384_scalar_to_montgomery,
    add: fiat_bp384_scalar_add,
    sub: fiat_bp384_scalar_sub,
    mul: fiat_bp384_scalar_mul,
    neg: fiat_bp384_scalar_opp,
    square: fiat_bp384_scalar_square,
    divstep_precomp: fiat_bp384_scalar_divstep_precomp,
    divstep: fiat_bp384_scalar_divstep,
    msat: fiat_bp384_scalar_msat,
    selectnz: fiat_bp384_scalar_selectznz
}

primefield::monty_field_reduce! {
    name: Scalar,
    params: ScalarParams,
    uint: U384,
}

elliptic_curve::scalar_impls!(BrainpoolP384r1, Scalar);
elliptic_curve::scalar_impls!(BrainpoolP384t1, Scalar);

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U384;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U384 = ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, U384};
    #[cfg(not(bp384_backend = "bignum"))]
    use super::{
        ScalarParams, fiat_bp384_scalar_montgomery_domain_field_element, fiat_bp384_scalar_msat,
        fiat_bp384_scalar_non_montgomery_domain_field_element, fiat_bp384_scalar_to_montgomery,
    };

    primefield::test_primefield!(Scalar, U384);

    #[cfg(not(bp384_backend = "bignum"))]
    primefield::test_fiat_monty_field_arithmetic!(
        name: Scalar,
        params: ScalarParams,
        uint: U384,
        non_mont: fiat_bp384_scalar_non_montgomery_domain_field_element,
        mont: fiat_bp384_scalar_montgomery_domain_field_element,
        to_mont: fiat_bp384_scalar_to_montgomery,
        msat: fiat_bp384_scalar_msat
    );
}
