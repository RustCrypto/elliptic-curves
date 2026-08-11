//! Field arithmetic modulo p = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3
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

use crate::U512;
use elliptic_curve::{
    bigint::cpubits,
    ff::PrimeField,
    ops::BatchInvert,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

// TODO(tarcieri): remove this when we can use `const _` to silence warnings
cpubits! {
    32 => {
        #[cfg(not(bp512_backend = "bigint"))]
        #[path = "field/bp512_32.rs"]
        #[allow(
            dead_code,
            clippy::identity_op,
            clippy::needless_lifetimes,
            clippy::unnecessary_cast,
            clippy::too_many_arguments
        )]
        mod field_impl;
    }
    64 => {
        #[cfg(not(bp512_backend = "bigint"))]
        #[path = "field/bp512_64.rs"]
        #[allow(
            dead_code,
            clippy::identity_op,
            clippy::needless_lifetimes,
            clippy::unnecessary_cast,
            clippy::too_many_arguments
        )]
        mod field_impl;
    }
}

#[cfg(not(bp512_backend = "bigint"))]
use self::field_impl::*;

/// Constant representing the modulus serialized as hex.
const MODULUS_HEX: &str = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U512,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 2,
    doc: "Montgomery parameters for brainpoolP512's field modulus"
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: U512,
    doc: "Element in the brainpoolP512 finite field modulo p"
}

#[cfg(bp512_backend = "bigint")]
primefield::monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U512
}

#[cfg(not(bp512_backend = "bigint"))]
primefield::fiat_monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U512,
    non_mont: fiat_bp512_non_montgomery_domain_field_element,
    mont: fiat_bp512_montgomery_domain_field_element,
    from_mont: fiat_bp512_from_montgomery,
    to_mont: fiat_bp512_to_montgomery,
    add: fiat_bp512_add,
    sub: fiat_bp512_sub,
    mul: fiat_bp512_mul,
    neg: fiat_bp512_opp,
    square: fiat_bp512_square,
    divstep_precomp: fiat_bp512_divstep_precomp,
    divstep: fiat_bp512_divstep,
    msat: fiat_bp512_msat,
    selectnz: fiat_bp512_selectznz
}

impl BatchInvert for FieldElement {}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U512};
    #[cfg(not(bp512_backend = "bigint"))]
    use super::{
        FieldParams, fiat_bp512_montgomery_domain_field_element, fiat_bp512_msat,
        fiat_bp512_non_montgomery_domain_field_element, fiat_bp512_to_montgomery,
    };

    primefield::test_primefield!(FieldElement, U512);

    #[cfg(not(bp512_backend = "bigint"))]
    primefield::test_fiat_monty_field_arithmetic!(
        name: FieldElement,
        params: FieldParams,
        uint: U512,
        non_mont: fiat_bp512_non_montgomery_domain_field_element,
        mont: fiat_bp512_montgomery_domain_field_element,
        to_mont: fiat_bp512_to_montgomery,
        msat: fiat_bp512_msat
    );
}
