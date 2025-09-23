//! Field arithmetic modulo p = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
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

#[cfg(target_pointer_width = "32")]
use fiat_crypto::sm2_32::*;
#[cfg(target_pointer_width = "64")]
use fiat_crypto::sm2_64::*;

use crate::U256;
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

/// Constant representing the modulus serialized as hex.
const MODULUS_HEX: &str = "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff";

primefield::monty_field_params! {
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U256,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 13,
    doc: "Montgomery parameters for SM2's field modulus `p = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff`"
}

primefield::monty_field_element! {
    name: FieldElement,
    params: FieldParams,
    uint: U256,
    doc: "Element in the SM2 finite field modulo `p = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff`"
}

primefield::monty_field_fiat_arithmetic!(
    FieldElement,
    FieldParams,
    U256,
    fiat_sm2_non_montgomery_domain_field_element,
    fiat_sm2_montgomery_domain_field_element,
    fiat_sm2_from_montgomery,
    fiat_sm2_to_montgomery,
    fiat_sm2_add,
    fiat_sm2_sub,
    fiat_sm2_mul,
    fiat_sm2_opp,
    fiat_sm2_square,
    fiat_sm2_divstep_precomp,
    fiat_sm2_divstep,
    fiat_sm2_msat,
    fiat_sm2_selectznz
);

#[cfg(test)]
mod tests {
    use super::{FieldElement, U256};
    primefield::test_primefield!(FieldElement, U256);
}
