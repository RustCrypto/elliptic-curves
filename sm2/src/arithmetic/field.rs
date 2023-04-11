//! Field arithmetic modulo p = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
//!
//! Arithmetic implementations are generated by fiat-crypto.
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

#[cfg_attr(target_pointer_width = "32", path = "field/sm2_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/sm2_64.rs")]
mod field_impl;

use self::field_impl::*;
use crate::{FieldBytes, Sm2, U256};
use core::{
    fmt::{self, Debug},
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, Neg, SubAssign},
};
use elliptic_curve::{
    bigint::Limb,
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

/// Constant representing the modulus serialized as hex.
const MODULUS_HEX: &str = "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff";

const MODULUS: U256 = U256::from_be_hex(MODULUS_HEX);

/// Element of the SM2 elliptic curve base field used for curve point coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(pub(super) U256);

primeorder::impl_mont_field_element!(
    Sm2,
    FieldElement,
    FieldBytes,
    U256,
    MODULUS,
    fiat_sm2_montgomery_domain_field_element,
    fiat_sm2_from_montgomery,
    fiat_sm2_to_montgomery,
    fiat_sm2_add,
    fiat_sm2_sub,
    fiat_sm2_mul,
    fiat_sm2_opp,
    fiat_sm2_square
);

impl Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement(0x{:X})", &self.0)
    }
}

impl FieldElement {
    /// Compute [`FieldElement`] inversion: `1 / self`.
    pub fn invert(&self) -> CtOption<Self> {
        CtOption::new(self.invert_unchecked(), !self.is_zero())
    }

    /// Returns the multiplicative inverse of self.
    ///
    /// Does not check that self is non-zero.
    const fn invert_unchecked(&self) -> Self {
        let words = primeorder::impl_bernstein_yang_invert!(
            self.0.as_words(),
            Self::ONE.0.to_words(),
            192,
            U256::LIMBS,
            Limb,
            fiat_sm2_from_montgomery,
            fiat_sm2_mul,
            fiat_sm2_opp,
            fiat_sm2_divstep_precomp,
            fiat_sm2_divstep,
            fiat_sm2_msat,
            fiat_sm2_selectznz,
        );

        Self(U256::from_words(words))
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
    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const TWO_INV: Self = Self::ZERO; // TODO
    const MULTIPLICATIVE_GENERATOR: Self = Self::ZERO; // TODO
    const S: u32 = 0; // TODO
    const ROOT_OF_UNITY: Self = Self::ZERO; // TODO
    const ROOT_OF_UNITY_INV: Self = Self::ZERO; // TODO
    const DELTA: Self = Self::ZERO; // TODO

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
