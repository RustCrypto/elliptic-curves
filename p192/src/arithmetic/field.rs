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

#![allow(
    clippy::should_implement_trait,
    clippy::suspicious_op_assign_impl,
    clippy::unused_unit,
    clippy::unnecessary_cast,
    clippy::too_many_arguments,
    clippy::identity_op,
    rustdoc::bare_urls
)]

#[cfg_attr(target_pointer_width = "32", path = "field/p192_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/p192_64.rs")]
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

primefield::monty_field_params!(
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U192,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 11,
    fe_name: "FieldElement",
    doc: "P-192 field modulus"
);

/// Element of the secp192r1 base field used for curve coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(
    pub(super) primefield::MontyFieldElement<FieldParams, { FieldParams::LIMBS }>,
);

primefield::field_element_type!(FieldElement, FieldParams, U192);

primefield::fiat_field_arithmetic!(
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

impl FieldElement {
    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Because p ≡ 3 mod 4 for secp192r1's base field modulus, sqrt can be done with only one
        // exponentiation via the computation of self^((p + 1) // 4) (mod p).
        let sqrt = self.pow_vartime(&[0xc000000000000000, 0xffffffffffffffff, 0x3fffffffffffffff]);
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U192};
    primefield::test_primefield!(FieldElement, U192);
}
