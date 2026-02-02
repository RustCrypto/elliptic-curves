//! Field arithmetic modulo p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1
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

use elliptic_curve::{
    bigint::{U384, cpubits},
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

// Default backend: fiat-crypto
cpubits! {
    32 => {
        #[cfg(not(p384_backend = "bignum"))]
        use fiat_crypto::p384_32::*;
    }
    64 => {
        #[cfg(not(p384_backend = "bignum"))]
        use fiat_crypto::p384_64::*;
    }
}

/// Constant representing the modulus
/// p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1
const MODULUS_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U384,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 19,
    doc: "Montgomery parameters for the NIST P-384 field modulus: `p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1`."
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: U384,
    doc: "Element in the finite field modulo `p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1`."
}

#[cfg(p384_backend = "bignum")]
primefield::monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U384
}

#[cfg(not(p384_backend = "bignum"))]
primefield::fiat_monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U384,
    non_mont: fiat_p384_non_montgomery_domain_field_element,
    mont: fiat_p384_montgomery_domain_field_element,
    from_mont: fiat_p384_from_montgomery,
    to_mont: fiat_p384_to_montgomery,
    add: fiat_p384_add,
    sub: fiat_p384_sub,
    mul: fiat_p384_mul,
    neg: fiat_p384_opp,
    square: fiat_p384_square,
    divstep_precomp: fiat_p384_divstep_precomp,
    divstep: fiat_p384_divstep,
    msat: fiat_p384_msat,
    selectnz: fiat_p384_selectznz
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U384};
    #[cfg(not(p384_backend = "bignum"))]
    use super::{
        FieldParams, fiat_p384_montgomery_domain_field_element, fiat_p384_msat,
        fiat_p384_non_montgomery_domain_field_element, fiat_p384_to_montgomery,
    };

    primefield::test_primefield!(FieldElement, U384);

    #[cfg(not(p384_backend = "bignum"))]
    primefield::test_fiat_monty_field_arithmetic!(
        name: FieldElement,
        params: FieldParams,
        uint: U384,
        non_mont: fiat_p384_non_montgomery_domain_field_element,
        mont: fiat_p384_montgomery_domain_field_element,
        to_mont: fiat_p384_to_montgomery,
        msat: fiat_p384_msat
    );
}
