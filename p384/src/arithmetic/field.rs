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

#[cfg(target_pointer_width = "32")]
use fiat_crypto::p384_32::*;
#[cfg(target_pointer_width = "64")]
use fiat_crypto::p384_64::*;

use elliptic_curve::{
    bigint::U384,
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

/// Constant representing the modulus
/// p = 2^{384} − 2^{128} − 2^{96} + 2^{32} − 1
const MODULUS_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";

primefield::monty_field_params!(
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U384,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 19,
    fe_name: "FieldElement",
    doc: "P-384 field modulus"
);

/// Element of the secp384r1 base field used for curve coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(
    pub(super) primefield::MontyFieldElement<FieldParams, { FieldParams::LIMBS }>,
);

primefield::monty_field_element!(FieldElement, FieldParams, U384);

primefield::monty_field_fiat_arithmetic!(
    FieldElement,
    FieldParams,
    U384,
    fiat_p384_non_montgomery_domain_field_element,
    fiat_p384_montgomery_domain_field_element,
    fiat_p384_from_montgomery,
    fiat_p384_to_montgomery,
    fiat_p384_add,
    fiat_p384_sub,
    fiat_p384_mul,
    fiat_p384_opp,
    fiat_p384_square,
    fiat_p384_divstep_precomp,
    fiat_p384_divstep,
    fiat_p384_msat,
    fiat_p384_selectznz
);

#[cfg(test)]
mod tests {
    use super::{FieldElement, U384};
    primefield::test_primefield!(FieldElement, U384);
}
