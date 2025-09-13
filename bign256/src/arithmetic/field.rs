//! Field arithmetic modulo p = 2^{256} − 189
//!
//! Arithmetic implementations are extracted Rust code from the Coq fiat-crypto
//! libraries.
//!
//! # License
//!
//! Copyright (c) 2015-2020 the fiat-crypto authors
//!
//! fiat-crypto is distributed under the terms of the MIT License, the
//! Apache License (Version 2.0), and the BSD 1-Clause License;
//! users may pick which license to apply.

#![allow(clippy::arithmetic_side_effects)]

#[cfg_attr(target_pointer_width = "32", path = "field/bign256_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/bign256_64.rs")]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod field_impl;

use self::field_impl::*;
use crate::U256;
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

/// Constant representing the modulus: p = 2^{256} − 189
const MODULUS_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43";

primefield::monty_field_params!(
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U256,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 2,
    fe_name: "FieldElement",
    doc: "P-256 field modulus"
);

/// Element of the bign-256 base field used for curve coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(
    pub(super) primefield::MontyFieldElement<FieldParams, { FieldParams::LIMBS }>,
);

primefield::monty_field_element!(FieldElement, FieldParams, U256);

primefield::monty_field_fiat_arithmetic!(
    FieldElement,
    FieldParams,
    U256,
    fiat_bign256_non_montgomery_domain_field_element,
    fiat_bign256_montgomery_domain_field_element,
    fiat_bign256_from_montgomery,
    fiat_bign256_to_montgomery,
    fiat_bign256_add,
    fiat_bign256_sub,
    fiat_bign256_mul,
    fiat_bign256_opp,
    fiat_bign256_square,
    fiat_bign256_divstep_precomp,
    fiat_bign256_divstep,
    fiat_bign256_msat,
    fiat_bign256_selectznz
);

impl FieldElement {
    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Because p ≡ 3 mod 4, sqrt can be done with only one
        // exponentiation via the computation of self^((p + 1) // 4) (mod p).
        let sqrt = self.pow_vartime(&[
            0xffffffffffffffd1,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x3fffffffffffffff,
        ]);
        CtOption::new(sqrt, (sqrt * sqrt).ct_eq(self))
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U256};
    primefield::test_primefield!(FieldElement, U256);
}
