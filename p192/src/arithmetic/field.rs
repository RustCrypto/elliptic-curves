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

#[cfg_attr(target_pointer_width = "32", path = "field/p192_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/p192_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod field_impl;

use self::field_impl::*;
use crate::U192;
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

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

primefield::monty_field_fiat_arithmetic!(
    FieldElement,
    FieldParams,
    U192,
    fiat_p192_non_montgomery_domain_field_element,
    fiat_p192_montgomery_domain_field_element,
    fiat_p192_from_montgomery,
    fiat_p192_to_montgomery,
    fiat_p192_add,
    fiat_p192_sub,
    fiat_p192_mul,
    fiat_p192_opp,
    fiat_p192_square,
    fiat_p192_divstep_precomp,
    fiat_p192_divstep,
    fiat_p192_msat,
    fiat_p192_selectznz
);

#[cfg(test)]
mod tests {
    use super::{FieldElement, U192};
    primefield::test_primefield!(FieldElement, U192);
}
