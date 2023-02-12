//! Field arithmetic modulo p = 2^{224} − 2^{96} + 1
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

#![allow(
    clippy::should_implement_trait,
    clippy::suspicious_op_assign_impl,
    clippy::unused_unit,
    clippy::unnecessary_cast,
    clippy::too_many_arguments,
    clippy::identity_op,
    rustdoc::bare_urls
)]

#[cfg_attr(target_pointer_width = "32", path = "field/p224_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/p224_64.rs")]
mod field_impl;

use self::field_impl::*;
use crate::{FieldBytes, NistP224, Uint};
use core::{
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, Neg, SubAssign},
};
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

/// Constant representing the modulus serialized as hex.
/// p = 2^{224} − 2^{96} + 1
const MODULUS_HEX: &str = "ffffffffffffffffffffffffffffffff000000000000000000000001";

#[cfg(target_pointer_width = "32")]
const MODULUS: Uint = Uint::from_be_hex(MODULUS_HEX);

#[cfg(target_pointer_width = "64")]
const MODULUS: Uint =
    Uint::from_be_hex("00000000ffffffffffffffffffffffffffffffff000000000000000000000001");

/// Element of the secp224r1 base field used for curve coordinates.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(super) Uint);

primeorder::impl_field_element!(
    NistP224,
    FieldElement,
    FieldBytes,
    Uint,
    MODULUS,
    fiat_p224_montgomery_domain_field_element,
    fiat_p224_from_montgomery,
    fiat_p224_to_montgomery,
    fiat_p224_add,
    fiat_p224_sub,
    fiat_p224_mul,
    fiat_p224_opp,
    fiat_p224_square
);

impl FieldElement {
    /// Compute [`FieldElement`] inversion: `1 / self`.
    pub fn invert(&self) -> CtOption<Self> {
        todo!("`invert` not yet implemented")
    }

    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        todo!("`sqrt` not yet implemented")
    }
}

impl PrimeField for FieldElement {
    type Repr = FieldBytes;

    const MODULUS: &'static str = MODULUS_HEX;
    const NUM_BITS: u32 = 224;
    const CAPACITY: u32 = 223;
    const TWO_INV: Self = Self::ZERO; // TODO: unimplemented
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(22);
    const S: u32 = 96;
    #[cfg(target_pointer_width = "32")]
    const ROOT_OF_UNITY: Self =
        Self::from_hex("395e40142de25856b7e38879fc315d7e6f6de3c1aa72e8c906610583");
    #[cfg(target_pointer_width = "64")]
    const ROOT_OF_UNITY: Self =
        Self::from_hex("00000000395e40142de25856b7e38879fc315d7e6f6de3c1aa72e8c906610583");
    const ROOT_OF_UNITY_INV: Self = Self::ZERO; // TODO: unimplemented
    #[cfg(target_pointer_width = "32")]
    const DELTA: Self = Self::from_hex("697b16135c4a62fca5c4f35ea6d5784cf3808e775aad34ec3d046867");
    #[cfg(target_pointer_width = "64")]
    const DELTA: Self =
        Self::from_hex("00000000697b16135c4a62fca5c4f35ea6d5784cf3808e775aad34ec3d046867");

    // NOTE: t = 0xffffffffffffffffffffffffffffffff

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
