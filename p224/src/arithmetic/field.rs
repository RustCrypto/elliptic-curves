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

#[cfg_attr(target_pointer_width = "32", path = "field/p224_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/p224_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod field_impl;

use self::field_impl::*;
use crate::Uint;
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

/// Constant representing the modulus serialized as hex.
/// p = 2^{224} − 2^{96} + 1
#[cfg(target_pointer_width = "32")]
const MODULUS_HEX: &str = "ffffffffffffffffffffffffffffffff000000000000000000000001";
#[cfg(target_pointer_width = "64")]
const MODULUS_HEX: &str = "00000000ffffffffffffffffffffffffffffffff000000000000000000000001";

primefield::monty_field_params!(
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: Uint,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 22,
    fe_name: "FieldElement",
    doc: "P-224 field modulus"
);

/// Element of the secp224r1 base field used for curve coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(
    pub(super) primefield::MontyFieldElement<FieldParams, { FieldParams::LIMBS }>,
);

primefield::monty_field_element!(FieldElement, FieldParams, Uint);

primefield::monty_field_fiat_arithmetic!(
    FieldElement,
    FieldParams,
    Uint,
    fiat_p224_non_montgomery_domain_field_element,
    fiat_p224_montgomery_domain_field_element,
    fiat_p224_from_montgomery,
    fiat_p224_to_montgomery,
    fiat_p224_add,
    fiat_p224_sub,
    fiat_p224_mul,
    fiat_p224_opp,
    fiat_p224_square,
    fiat_p224_divstep_precomp,
    fiat_p224_divstep,
    fiat_p224_msat,
    fiat_p224_selectznz
);

#[cfg(test)]
mod tests {
    use super::{FieldElement, Uint};
    primefield::test_primefield!(FieldElement, Uint);
}
