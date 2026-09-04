//! Field arithmetic modulo p = 2^{256} − 189
//!
//! Arithmetic implementations are extracted Rust code from the Coq fiat-crypto
//! libraries.
//!
//! # License
//!
//! Copyright (c) 2015-2020 the fiat-crypto authors
//!
//! fiat-crypto is distributed under the terms of the MIT License, the
//! Apache License (Version 2.0), and the BSD 1-Clause License;
//! users may pick which license to apply.

#![allow(clippy::arithmetic_side_effects)]

use crate::U256;
use elliptic_curve::{
    ff::PrimeField,
    ops::BatchInvert,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

#[cfg(not(bignp256_backend = "bigint"))]
use elliptic_curve::bigint::cpubits;

// TODO(tarcieri): remove this when we can use `const _` to silence warnings
#[cfg(not(bignp256_backend = "bigint"))]
cpubits! {
    32 => {
        #[path = "field/bignp256_32.rs"]
        #[allow(
            dead_code,
            clippy::cast_possible_truncation,
            clippy::cast_possible_wrap,
            clippy::cast_sign_loss,
            clippy::identity_op,
            clippy::needless_lifetimes,
            clippy::too_many_arguments,
            clippy::unnecessary_cast
        )]
        mod field_impl;
    }
    64 => {
        #[path = "field/bignp256_64.rs"]
        #[allow(
            dead_code,
            clippy::cast_possible_truncation,
            clippy::cast_possible_wrap,
            clippy::cast_sign_loss,
            clippy::identity_op,
            clippy::needless_lifetimes,
            clippy::too_many_arguments,
            clippy::unnecessary_cast
        )]
        mod field_impl;
    }
}

#[cfg(not(bignp256_backend = "bigint"))]
use self::field_impl::*;

/// Constant representing the modulus: p = 2^{256} − 189
const MODULUS_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43";

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U256,
    byte_order: primefield::ByteOrder::LittleEndian,
    multiplicative_generator: 2,
    doc: "Montgomery parameters for the bign-curve256v1 field modulus p = 2^{256} − 189"
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: U256,
    doc: "Element in the bign-curve256v1 finite field modulo p = 2^{256} − 189"
}

#[cfg(bignp256_backend = "bigint")]
primefield::monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U256
}

#[cfg(not(bignp256_backend = "bigint"))]
primefield::fiat_monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U256,
    non_mont: fiat_bignp256_non_montgomery_domain_field_element,
    mont: fiat_bignp256_montgomery_domain_field_element,
    from_mont: fiat_bignp256_from_montgomery,
    to_mont: fiat_bignp256_to_montgomery,
    add: fiat_bignp256_add,
    sub: fiat_bignp256_sub,
    mul: fiat_bignp256_mul,
    neg: fiat_bignp256_opp,
    square: fiat_bignp256_square,
    divstep_precomp: fiat_bignp256_divstep_precomp,
    divstep: fiat_bignp256_divstep,
    msat: fiat_bignp256_msat,
    selectnz: fiat_bignp256_selectznz
}

impl BatchInvert for FieldElement {}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U256};
    #[cfg(not(bignp256_backend = "bigint"))]
    use super::{
        FieldParams, fiat_bignp256_montgomery_domain_field_element, fiat_bignp256_msat,
        fiat_bignp256_non_montgomery_domain_field_element, fiat_bignp256_to_montgomery,
    };

    primefield::test_primefield!(FieldElement, U256);

    #[cfg(not(bignp256_backend = "bigint"))]
    primefield::test_fiat_monty_field_arithmetic!(
        name: FieldElement,
        params: FieldParams,
        uint: U256,
        non_mont: fiat_bignp256_non_montgomery_domain_field_element,
        mont: fiat_bignp256_montgomery_domain_field_element,
        to_mont: fiat_bignp256_to_montgomery,
        msat: fiat_bignp256_msat
    );
}
