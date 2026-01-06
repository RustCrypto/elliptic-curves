//! Field arithmetic modulo p = 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377
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

#[cfg(not(bp256_backend = "bignum"))]
#[cfg_attr(target_pointer_width = "32", path = "field/bp256_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/bp256_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod field_impl;

use crate::U256;
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

#[cfg(not(bp256_backend = "bignum"))]
use self::field_impl::*;

/// Constant representing the modulus serialized as hex.
const MODULUS_HEX: &str = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U256,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 11,
    doc: "Montgomery parameters for brainpoolP256's field modulus"
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: U256,
    doc: "Element in the brainpoolP256 finite field modulo p"
}

#[cfg(bp256_backend = "bignum")]
primefield::monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U256
}

#[cfg(not(bp256_backend = "bignum"))]
primefield::fiat_monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U256,
    non_mont: fiat_bp256_non_montgomery_domain_field_element,
    mont: fiat_bp256_montgomery_domain_field_element,
    from_mont: fiat_bp256_from_montgomery,
    to_mont: fiat_bp256_to_montgomery,
    add: fiat_bp256_add,
    sub: fiat_bp256_sub,
    mul: fiat_bp256_mul,
    neg: fiat_bp256_opp,
    square: fiat_bp256_square,
    divstep_precomp: fiat_bp256_divstep_precomp,
    divstep: fiat_bp256_divstep,
    msat: fiat_bp256_msat,
    selectnz: fiat_bp256_selectznz
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U256};
    #[cfg(not(bp256_backend = "bignum"))]
    use super::{
        FieldParams, fiat_bp256_montgomery_domain_field_element, fiat_bp256_msat,
        fiat_bp256_non_montgomery_domain_field_element, fiat_bp256_to_montgomery,
    };

    primefield::test_primefield!(FieldElement, U256);

    #[cfg(not(bp256_backend = "bignum"))]
    primefield::test_fiat_monty_field_arithmetic!(
        name: FieldElement,
        params: FieldParams,
        uint: U256,
        non_mont: fiat_bp256_non_montgomery_domain_field_element,
        mont: fiat_bp256_montgomery_domain_field_element,
        to_mont: fiat_bp256_to_montgomery,
        msat: fiat_bp256_msat
    );
}
