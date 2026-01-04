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

use self::scalar_impl::*;
use crate::{BrainpoolP384r1, BrainpoolP384t1, FieldBytes, ORDER, ORDER_HEX, U384};
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
    uint: U384,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 2,
    doc: "Montgomery parameters for brainpoolP384's scalar modulus"
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: U384,
    doc: "Element in the brainpoolP256 scalar field modulo n"
}

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

impl Reduce<U384> for Scalar {
    fn reduce(w: &U384) -> Self {
        let (r, underflow) = w.borrowing_sub(&ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U384::conditional_select(w, &r, !underflow))
    }
}

impl Reduce<FieldBytes> for Scalar {
    #[inline]
    fn reduce(bytes: &FieldBytes) -> Self {
        Self::reduce(&U384::from_be_byte_array(*bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, U384};
    primefield::test_primefield!(Scalar, U384);
}
