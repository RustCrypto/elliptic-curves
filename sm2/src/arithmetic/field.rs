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

primefield::monty_field_params!(
    name: FieldParams,
    modulus: MODULUS_HEX,
    uint: U256,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 13,
    fe_name: "FieldElement",
    doc: "SM2 field modulus"
);

/// Element of the SM2 elliptic curve base field used for curve point coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(
    pub(super) primefield::MontyFieldElement<FieldParams, { FieldParams::LIMBS }>,
);

primefield::monty_field_element!(FieldElement, FieldParams, U256);

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

impl FieldElement {
    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        /// Because p ≡ 3 mod 4 for SM2's base field modulus, sqrt can be done with only one
        /// exponentiation via the computation of self^((p + 1) // 4) (mod p).
        const EXP: U256 =
            U256::from_be_hex("3fffffffbfffffffffffffffffffffffffffffffc00000004000000000000000");
        let sqrt = self.pow_vartime(&EXP);
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U256};
    primefield::test_primefield!(FieldElement, U256);
}
