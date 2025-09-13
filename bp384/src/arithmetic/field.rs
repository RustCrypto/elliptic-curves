//! Field arithmetic modulo p = 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53
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

#[cfg_attr(target_pointer_width = "32", path = "field/bp384_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/bp384_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod field_impl;

use self::field_impl::*;
use crate::U384;
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

/// Constant representing the modulus serialized as hex.
const MODULUS_HEX: &str = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53";

primefield::monty_field_params!(
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U384,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 3,
    fe_name: "FieldElement",
    doc: "brainpoolP384 field modulus"
);

/// Element of the brainpoolP384's base field used for curve point coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(
    pub(super) primefield::MontyFieldElement<FieldParams, { FieldParams::LIMBS }>,
);

primefield::monty_field_element!(FieldElement, FieldParams, U384);

primefield::monty_field_fiat_arithmetic!(
    FieldElement,
    FieldParams,
    U384,
    fiat_bp384_non_montgomery_domain_field_element,
    fiat_bp384_montgomery_domain_field_element,
    fiat_bp384_from_montgomery,
    fiat_bp384_to_montgomery,
    fiat_bp384_add,
    fiat_bp384_sub,
    fiat_bp384_mul,
    fiat_bp384_opp,
    fiat_bp384_square,
    fiat_bp384_divstep_precomp,
    fiat_bp384_divstep,
    fiat_bp384_msat,
    fiat_bp384_selectznz
);

impl FieldElement {
    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Because p ≡ 3 mod 4 for brainpoolP384's base field modulus, sqrt can
        // be implemented with only one exponentiation via the computation of
        // self^((p + 1) // 4) (mod p).
        let sqrt = self.pow_vartime(&[
            0x61d1c004cc41fb15,
            0xeb34e9ca6407469c,
            0x04ac76865fedc448,
            0xc54bdc427b5515ad,
            0x03d75bdf94399077,
            0x232e47a0a8ce1b4a,
        ]);
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U384};
    primefield::test_primefield!(FieldElement, U384);
}
