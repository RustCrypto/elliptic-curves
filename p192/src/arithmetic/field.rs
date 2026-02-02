//! Field arithmetic modulo p = 2^{192} − 2^{64} - 1
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

use crate::U192;
use elliptic_curve::{
    bigint::cpubits,
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

// TODO(tarcieri): remove this when we can use `const _` to silence warnings
cpubits! {
    32 => {
        #[cfg(not(p192_backend = "bignum"))]
        #[path = "field/p192_32.rs"]
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
        #[cfg(not(p192_backend = "bignum"))]
        #[path = "field/p192_64.rs"]
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

#[cfg(not(p192_backend = "bignum"))]
use self::field_impl::*;

/// Constant representing the modulus serialized as hex.
/// p = 2^{192} − 2^{64} - 1
const MODULUS_HEX: &str = "fffffffffffffffffffffffffffffffeffffffffffffffff";

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U192,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 11,
    doc: "Montgomery parameters for the NIST P-192 field modulus: `p = 2^{192} − 2^{64} - 1`."
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: U192,
    doc: "Element in the finite field modulo `p = 2^{192} − 2^{64} - 1`."
}

#[cfg(p192_backend = "bignum")]
primefield::monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U192
}

#[cfg(not(p192_backend = "bignum"))]
primefield::fiat_monty_field_arithmetic! {
    name: FieldElement,
    params: FieldParams,
    uint: U192,
    non_mont: fiat_p192_non_montgomery_domain_field_element,
    mont: fiat_p192_montgomery_domain_field_element,
    from_mont: fiat_p192_from_montgomery,
    to_mont: fiat_p192_to_montgomery,
    add: fiat_p192_add,
    sub: fiat_p192_sub,
    mul: fiat_p192_mul,
    neg: fiat_p192_opp,
    square: fiat_p192_square,
    divstep_precomp: fiat_p192_divstep_precomp,
    divstep: fiat_p192_divstep,
    msat: fiat_p192_msat,
    selectnz: fiat_p192_selectznz
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U192};
    #[cfg(not(p192_backend = "bignum"))]
    use super::{
        FieldParams, fiat_p192_montgomery_domain_field_element, fiat_p192_msat,
        fiat_p192_non_montgomery_domain_field_element, fiat_p192_to_montgomery,
    };

    primefield::test_primefield!(FieldElement, U192);

    #[cfg(not(p192_backend = "bignum"))]
    primefield::test_fiat_monty_field_arithmetic!(
        name: FieldElement,
        params: FieldParams,
        uint: U192,
        non_mont: fiat_p192_non_montgomery_domain_field_element,
        mont: fiat_p192_montgomery_domain_field_element,
        to_mont: fiat_p192_to_montgomery,
        msat: fiat_p192_msat
    );
}
