//! Field arithmetic modulo p = 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377
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

#[cfg_attr(target_pointer_width = "32", path = "field/bp256_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/bp256_64.rs")]
mod field_impl;

use self::field_impl::*;
use crate::{FieldBytes, U256};
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

/// Constant representing the modulus serialized as hex.
const MODULUS_HEX: &str = "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377";

const MODULUS: U256 = U256::from_be_hex(MODULUS_HEX);

/// Element of the brainpoolP256's base field used for curve point coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(pub(super) U256);

primefield::field_element_type!(
    FieldElement,
    FieldBytes,
    U256,
    MODULUS,
    crate::decode_field_bytes,
    crate::encode_field_bytes
);

primefield::fiat_field_arithmetic!(
    FieldElement,
    FieldBytes,
    U256,
    fiat_bp256_non_montgomery_domain_field_element,
    fiat_bp256_montgomery_domain_field_element,
    fiat_bp256_from_montgomery,
    fiat_bp256_to_montgomery,
    fiat_bp256_add,
    fiat_bp256_sub,
    fiat_bp256_mul,
    fiat_bp256_opp,
    fiat_bp256_square,
    fiat_bp256_divstep_precomp,
    fiat_bp256_divstep,
    fiat_bp256_msat,
    fiat_bp256_selectznz
);

impl FieldElement {
    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Because p ≡ 3 mod 4 for brainpoolP256's base field modulus, sqrt can
        // be implemented with only one exponentiation via the computation of
        // self^((p + 1) // 4) (mod p).
        let sqrt = self.pow_vartime(&[
            0x0804d20747db94de,
            0x9b8efd88f549880a,
            0x0f9982a42760e35c,
            0x2a7ed5f6e87baa6f,
        ]);
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }
}

impl PrimeField for FieldElement {
    type Repr = FieldBytes;

    const MODULUS: &'static str = MODULUS_HEX;
    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(11);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self =
        Self::from_hex("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5376");
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    const DELTA: Self = Self::from_u64(121);

    #[inline]
    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        Self::from_bytes(&bytes)
    }

    #[inline]
    fn to_repr(&self) -> FieldBytes {
        self.to_bytes()
    }

    #[inline]
    fn is_odd(&self) -> Choice {
        self.is_odd()
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, U256};
    primefield::test_primefield!(FieldElement, U256);
}
