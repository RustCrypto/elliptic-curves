//! brainpoolP512 scalar field elements.
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

use crate::{BrainpoolP512r1, BrainpoolP512t1, ORDER, ORDER_HEX, U512};
use elliptic_curve::{
    bigint::cpubits,
    ff::PrimeField,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, CtOption},
};
use primeorder::wnaf;

// TODO(tarcieri): remove this when we can use `const _` to silence warnings
cpubits! {
    32 => {
        #[cfg(not(bp512_backend = "bigint"))]
        #[path = "scalar/bp512_scalar_32.rs"]
        #[allow(
            dead_code,
            clippy::identity_op,
            clippy::needless_lifetimes,
            clippy::unnecessary_cast,
            clippy::too_many_arguments
        )]
        mod scalar_impl;
    }
    64 => {
        #[cfg(not(bp512_backend = "bigint"))]
        #[path = "scalar/bp512_scalar_64.rs"]
        #[allow(
            dead_code,
            clippy::identity_op,
            clippy::needless_lifetimes,
            clippy::unnecessary_cast,
            clippy::too_many_arguments
        )]
        mod scalar_impl;
    }
}

#[cfg(not(bp512_backend = "bigint"))]
use self::scalar_impl::*;

#[cfg(doc)]
use core::ops::{Add, Mul, Sub};

primefield::monty_field_params! {
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: U512,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 7,
    doc: "Montgomery parameters for brainpoolP512's scalar modulus"
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: U512,
    doc: "Element in the brainpoolP512 scalar field modulo n"
}

#[cfg(bp512_backend = "bigint")]
primefield::monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U512
}

#[cfg(not(bp512_backend = "bigint"))]
primefield::fiat_monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U512,
    non_mont: fiat_bp512_scalar_non_montgomery_domain_field_element,
    mont: fiat_bp512_scalar_montgomery_domain_field_element,
    from_mont: fiat_bp512_scalar_from_montgomery,
    to_mont: fiat_bp512_scalar_to_montgomery,
    add: fiat_bp512_scalar_add,
    sub: fiat_bp512_scalar_sub,
    mul: fiat_bp512_scalar_mul,
    neg: fiat_bp512_scalar_opp,
    square: fiat_bp512_scalar_square,
    divstep_precomp: fiat_bp512_scalar_divstep_precomp,
    divstep: fiat_bp512_scalar_divstep,
    msat: fiat_bp512_scalar_msat,
    selectnz: fiat_bp512_scalar_selectznz
}

primefield::monty_field_reduce! {
    name: Scalar,
    params: ScalarParams,
    uint: U512,
}

elliptic_curve::scalar_impls!(BrainpoolP512r1, Scalar);
elliptic_curve::scalar_impls!(BrainpoolP512t1, Scalar);

// A 512-bit scalar requires `hybrid-array`'s `ArraySize` implementation for U513.
wnaf::impl_wnaf_size_for_scalar!(Scalar);

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U512;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U512 = ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, U512};
    #[cfg(not(bp512_backend = "bigint"))]
    use super::{
        ScalarParams, fiat_bp512_scalar_montgomery_domain_field_element, fiat_bp512_scalar_msat,
        fiat_bp512_scalar_non_montgomery_domain_field_element, fiat_bp512_scalar_to_montgomery,
    };

    primefield::test_primefield!(Scalar, U512);

    #[cfg(not(bp512_backend = "bigint"))]
    primefield::test_fiat_monty_field_arithmetic!(
        name: Scalar,
        params: ScalarParams,
        uint: U512,
        non_mont: fiat_bp512_scalar_non_montgomery_domain_field_element,
        mont: fiat_bp512_scalar_montgomery_domain_field_element,
        to_mont: fiat_bp512_scalar_to_montgomery,
        msat: fiat_bp512_scalar_msat
    );
}
