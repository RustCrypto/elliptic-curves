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

#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::should_implement_trait,
    clippy::suspicious_op_assign_impl,
    clippy::unused_unit,
    clippy::unnecessary_cast,
    clippy::too_many_arguments,
    clippy::identity_op,
    rustdoc::bare_urls
)]

#[cfg_attr(target_pointer_width = "32", path = "field/sm2_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/sm2_64.rs")]
mod field_impl;

use self::field_impl::*;
use crate::{FieldBytes, Sm2, U256};
use elliptic_curve::{
    FieldBytesEncoding,
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

/// Constant representing the modulus serialized as hex.
const MODULUS_HEX: &str = "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff";

const MODULUS: U256 = U256::from_be_hex(MODULUS_HEX);

/// Element of the SM2 elliptic curve base field used for curve point coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(pub(super) U256);

primefield::field_element_type!(
    FieldElement,
    FieldBytes,
    U256,
    MODULUS,
    FieldBytesEncoding::<Sm2>::decode_field_bytes,
    FieldBytesEncoding::<Sm2>::encode_field_bytes
);

primefield::fiat_field_arithmetic!(
    FieldElement,
    FieldBytes,
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
        // Because p ≡ 3 mod 4 for SM2's base field modulus, sqrt can be done with only one
        // exponentiation via the computation of self^((p + 1) // 4) (mod p).
        let sqrt = self.pow_vartime(&[
            0x4000000000000000,
            0xffffffffc0000000,
            0xffffffffffffffff,
            0x3fffffffbfffffff,
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
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(13);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self =
        Self::from_hex("fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffe");
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    const DELTA: Self = Self::from_u64(169);

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
