//! Field arithmetic modulo p = 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53
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
#[cfg_attr(target_pointer_width = "32", path = "field/bp384_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/bp384_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod field_impl;

use crate::U384;
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

#[cfg(not(bp384_backend = "bignum"))]
use self::field_impl::*;

/// Constant representing the modulus serialized as hex.
const MODULUS_HEX: &str = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U384,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 3,
    doc: "Montgomery parameters for brainpoolP384's field modulus"
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: U384,
    doc: "Element in the brainpoolP384 finite field modulo p"
}

#[cfg(bp384_backend = "bignum")]
primefield::monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U384
}

#[cfg(not(bp384_backend = "bignum"))]
primefield::fiat_monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U384,
    non_mont: fiat_bp384_non_montgomery_domain_field_element,
    mont: fiat_bp384_montgomery_domain_field_element,
    from_mont: fiat_bp384_from_montgomery,
    to_mont: fiat_bp384_to_montgomery,
    add: fiat_bp384_add,
    sub: fiat_bp384_sub,
    mul: fiat_bp384_mul,
    neg: fiat_bp384_opp,
    square: fiat_bp384_square,
    divstep_precomp: fiat_bp384_divstep_precomp,
    divstep: fiat_bp384_divstep,
    msat: fiat_bp384_msat,
    selectnz: fiat_bp384_selectznz
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U384};
    #[cfg(not(bp384_backend = "bignum"))]
    use super::{
        FieldParams, fiat_bp384_montgomery_domain_field_element, fiat_bp384_msat,
        fiat_bp384_non_montgomery_domain_field_element, fiat_bp384_to_montgomery,
    };

    primefield::test_primefield!(FieldElement, U384);

    #[cfg(not(bp384_backend = "bignum"))]
    primefield::test_fiat_monty_field_arithmetic!(
        name: FieldElement,
        params: FieldParams,
        uint: U384,
        non_mont: fiat_bp384_non_montgomery_domain_field_element,
        mont: fiat_bp384_montgomery_domain_field_element,
        to_mont: fiat_bp384_to_montgomery,
        msat: fiat_bp384_msat
    );
}
