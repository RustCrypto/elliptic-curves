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
use crate::{FieldBytes, NistP192, U192};
use elliptic_curve::{
    FieldBytesEncoding,
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

/// Constant representing the modulus serialized as hex.
/// p = 2^{192} − 2^{64} - 1
const MODULUS_HEX: &str = "fffffffffffffffffffffffffffffffeffffffffffffffff";

const MODULUS: U192 = U192::from_be_hex(MODULUS_HEX);

/// Element of the secp192r1 base field used for curve coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(pub(super) U192);

primefield::field_element_type!(
    FieldElement,
    FieldBytes,
    U192,
    MODULUS,
    FieldBytesEncoding::<NistP192>::decode_field_bytes,
    FieldBytesEncoding::<NistP192>::encode_field_bytes
);

primefield::fiat_field_arithmetic!(
    FieldElement,
    FieldBytes,
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

impl PrimeField for FieldElement {
    type Repr = FieldBytes;

    const MODULUS: &'static str = MODULUS_HEX;
    const NUM_BITS: u32 = 192;
    const CAPACITY: u32 = 191;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(11);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self = Self::from_hex("fffffffffffffffffffffffffffffffefffffffffffffffe");
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
    use super::{FieldElement, U192};
    primefield::test_primefield!(FieldElement, U192);
}
