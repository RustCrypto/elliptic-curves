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

#[cfg_attr(target_pointer_width = "32", path = "field/bignp256_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/bignp256_64.rs")]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod field_impl;

use self::field_impl::*;
use crate::U256;
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

/// Constant representing the modulus: p = 2^{256} − 189
const MODULUS_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43";

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U256,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 2,
    doc: "Montgomery parameters for the bign-curve256v1 field modulus p = 2^{256} − 189"
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: U256,
    doc: "Element in the bign-curve256v1 finite field modulo p = 2^{256} − 189"
}

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

#[cfg(test)]
mod tests {
    use super::{FieldElement, U256};
    primefield::test_primefield!(FieldElement, U256);
}
