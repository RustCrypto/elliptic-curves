//! brainpoolP384 scalar field elements.
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

#[cfg_attr(target_pointer_width = "32", path = "scalar/bp384_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/bp384_scalar_64.rs")]
mod scalar_impl;

use self::scalar_impl::*;
use crate::{BrainpoolP384r1, BrainpoolP384t1, FieldBytes, ORDER, ORDER_HEX, U384};
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

/// Element of the brainpoolP384's scalar field.
#[derive(Clone, Copy, PartialOrd, Ord)]
pub struct Scalar(pub(super) U384);

primefield::field_element_type!(
    Scalar,
    FieldBytes,
    U384,
    ORDER,
    crate::decode_field_bytes,
    crate::encode_field_bytes
);

primefield::fiat_field_arithmetic!(
    Scalar,
    FieldBytes,
    U384,
    fiat_bp384_scalar_non_montgomery_domain_field_element,
    fiat_bp384_scalar_montgomery_domain_field_element,
    fiat_bp384_scalar_from_montgomery,
    fiat_bp384_scalar_to_montgomery,
    fiat_bp384_scalar_add,
    fiat_bp384_scalar_sub,
    fiat_bp384_scalar_mul,
    fiat_bp384_scalar_opp,
    fiat_bp384_scalar_square,
    fiat_bp384_scalar_divstep_precomp,
    fiat_bp384_scalar_divstep,
    fiat_bp384_scalar_msat,
    fiat_bp384_scalar_selectznz
);

elliptic_curve::scalar_impls!(BrainpoolP384r1, Scalar);
elliptic_curve::scalar_impls!(BrainpoolP384t1, Scalar);

impl Scalar {
    /// Atkin algorithm for q mod 8 = 5
    /// <https://eips.ethereum.org/assets/eip-3068/2012-685_Square_Root_Even_Ext.pdf>
    /// (page 10, algorithm 3)
    pub fn sqrt(&self) -> CtOption<Self> {
        let w = &[
            0x077106405d208cac,
            0xf9e756d5ed6ff862,
            0x63e2cdcd958084b4,
            0xe2a5ee213daa8ad6,
            0x01ebadefca1cc83b,
            0x119723d054670da5,
        ];
        let t = Self::from_u64(2).pow_vartime(w);
        let a1 = self.pow_vartime(w);
        let a0 = (a1.square() * self).square();
        let b = t * a1;
        let ab = self * &b;
        let i = Self::from_u64(2) * ab * b;
        let x = ab * (i - Self::ONE);
        CtOption::new(x, !a0.ct_eq(&-Self::ONE))
    }
}

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U384;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U384 = ORDER.shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const MODULUS: &'static str = ORDER_HEX;
    const NUM_BITS: u32 = 384;
    const CAPACITY: u32 = 383;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(2);
    const S: u32 = 2;
    const ROOT_OF_UNITY: Self = Self::from_hex(
        "76cdc6369fb54dde55a851fce47cc5f830bb074c85684b3ee476be128dc50cfa8602aeecf53a1982fcf3b95f8d4258ff",
    );
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    const DELTA: Self = Self::from_u64(16);

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

impl Reduce<U384> for Scalar {
    type Bytes = FieldBytes;

    fn reduce(w: U384) -> Self {
        let (r, underflow) = w.borrowing_sub(&ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U384::conditional_select(&w, &r, !underflow))
    }

    #[inline]
    fn reduce_bytes(bytes: &FieldBytes) -> Self {
        Self::reduce(U384::from_be_byte_array(*bytes))
    }
}

impl TryFrom<U384> for Scalar {
    type Error = Error;

    fn try_from(w: U384) -> Result<Self> {
        Option::from(Self::from_uint(w)).ok_or(Error)
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, U384};
    primefield::test_primefield!(Scalar, U384);
}
