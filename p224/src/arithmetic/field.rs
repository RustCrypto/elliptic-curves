//! Field arithmetic modulo p = 2^{224} − 2^{96} + 1
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

use crate::Uint;
use elliptic_curve::{
    bigint::cpubits,
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

// TODO(tarcieri): remove this when we can use `const _` to silence warnings
cpubits! {
    32 => {
        #[cfg(not(p224_backend = "bignum"))]
        #[path = "field/p224_32.rs"]
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
        #[cfg(not(p224_backend = "bignum"))]
        #[path = "field/p224_64.rs"]
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

#[cfg(not(p224_backend = "bignum"))]
use self::field_impl::*;

/// Constant representing the modulus serialized as hex.
/// p = 2^{224} − 2^{96} + 1
const MODULUS_HEX: &str = {
    cpubits! {
        32 => { "ffffffffffffffffffffffffffffffff000000000000000000000001" }
        64 => { "00000000ffffffffffffffffffffffffffffffff000000000000000000000001" }
    }
};

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: Uint,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 22,
    doc: "Montgomery parameters for the NIST P-224 field modulus: `p = 2^{224} − 2^{96} + 1`."
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: Uint,
    doc: "Element in the finite field modulo `p = 2^{224} − 2^{96} + 1`."
}

#[cfg(p224_backend = "bignum")]
primefield::monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: Uint
}

#[cfg(not(p224_backend = "bignum"))]
primefield::fiat_monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: Uint,
    non_mont: fiat_p224_non_montgomery_domain_field_element,
    mont: fiat_p224_montgomery_domain_field_element,
    from_mont: fiat_p224_from_montgomery,
    to_mont: fiat_p224_to_montgomery,
    add: fiat_p224_add,
    sub: fiat_p224_sub,
    mul: fiat_p224_mul,
    neg: fiat_p224_opp,
    square: fiat_p224_square,
    divstep_precomp: fiat_p224_divstep_precomp,
    divstep: fiat_p224_divstep,
    msat: fiat_p224_msat,
    selectnz: fiat_p224_selectznz
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, Uint};

    #[cfg(not(p224_backend = "bignum"))]
    use super::{
        FieldParams, fiat_p224_montgomery_domain_field_element, fiat_p224_msat,
        fiat_p224_non_montgomery_domain_field_element, fiat_p224_to_montgomery,
    };

    primefield::test_primefield!(FieldElement, Uint);

    #[cfg(not(p224_backend = "bignum"))]
    primefield::test_fiat_monty_field_arithmetic!(
        name: FieldElement,
        params: FieldParams,
        uint: Uint,
        non_mont: fiat_p224_non_montgomery_domain_field_element,
        mont: fiat_p224_montgomery_domain_field_element,
        to_mont: fiat_p224_to_montgomery,
        msat: fiat_p224_msat
    );
}
