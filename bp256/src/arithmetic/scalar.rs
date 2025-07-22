//! brainpoolP256 scalar field elements.
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

#[cfg_attr(target_pointer_width = "32", path = "scalar/bp256_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/bp256_scalar_64.rs")]
mod scalar_impl;

use self::scalar_impl::*;
use crate::{BrainpoolP256r1, BrainpoolP256t1, FieldBytes, ORDER, ORDER_HEX, U256};
use elliptic_curve::{
    Error, Result,
    bigint::{ArrayEncoding, Limb},
    ff::PrimeField,
    ops::Reduce,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption},
};

#[cfg(doc)]
use core::ops::{Add, Mul, Sub};

/// Element of brainpoolP256's scalar field.
#[derive(Clone, Copy, PartialOrd, Ord)]
pub struct Scalar(pub(super) U256);

primefield::field_element_type!(
    Scalar,
    FieldBytes,
    U256,
    ORDER,
    crate::decode_field_bytes,
    crate::encode_field_bytes
);

primefield::fiat_field_arithmetic!(
    Scalar,
    FieldBytes,
    U256,
    fiat_bp256_scalar_non_montgomery_domain_field_element,
    fiat_bp256_scalar_montgomery_domain_field_element,
    fiat_bp256_scalar_from_montgomery,
    fiat_bp256_scalar_to_montgomery,
    fiat_bp256_scalar_add,
    fiat_bp256_scalar_sub,
    fiat_bp256_scalar_mul,
    fiat_bp256_scalar_opp,
    fiat_bp256_scalar_square,
    fiat_bp256_scalar_divstep_precomp,
    fiat_bp256_scalar_divstep,
    fiat_bp256_scalar_msat,
    fiat_bp256_scalar_selectznz
);

elliptic_curve::scalar_impls!(BrainpoolP256r1, Scalar);
elliptic_curve::scalar_impls!(BrainpoolP256t1, Scalar);

impl Scalar {
    /// Returns the square root of self mod n, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Because n ≡ 3 mod 4 for brainpoolP256's scalar field modulus, sqrt
        // can be implemented with only one exponentiation via the computation
        // of self^((n + 1) // 4) (mod n).
        let sqrt = self.pow_vartime(&[
            0xe40783a0a5d215aa,
            0x630e5ea8ed5869bd,
            0x0f9982a42760e35c,
            0x2a7ed5f6e87baa6f,
        ]);
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }
}

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U256;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U256 = ORDER.shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const MODULUS: &'static str = ORDER_HEX;
    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(3);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self =
        Self::from_hex("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a6");
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    const DELTA: Self = Self::from_u64(9);

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

impl Reduce<U256> for Scalar {
    type Bytes = FieldBytes;

    fn reduce(w: U256) -> Self {
        let (r, underflow) = w.borrowing_sub(&ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U256::conditional_select(&w, &r, !underflow))
    }

    #[inline]
    fn reduce_bytes(bytes: &FieldBytes) -> Self {
        Self::reduce(U256::from_be_byte_array(*bytes))
    }
}

impl TryFrom<U256> for Scalar {
    type Error = Error;

    fn try_from(w: U256) -> Result<Self> {
        Option::from(Self::from_uint(w)).ok_or(Error)
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, U256};
    primefield::test_primefield!(Scalar, U256);
}
