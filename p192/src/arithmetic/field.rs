//! Field arithmetic modulo p = 2^{192} − 2^{64} - 1
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

#[cfg_attr(target_pointer_width = "32", path = "field/p192_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/p192_64.rs")]
mod field_impl;

use self::field_impl::*;
use crate::{FieldBytes, NistP192, U192};
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
/// p = 2^{192} − 2^{64} - 1
const MODULUS_HEX: &str = "fffffffffffffffffffffffffffffffeffffffffffffffff";

const MODULUS: U192 = U192::from_be_hex(MODULUS_HEX);

/// Element of the secp192r1 base field used for curve coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(pub(super) U192);

primeorder::impl_mont_field_element!(
    NistP192,
    FieldElement,
    FieldBytes,
    U192,
    MODULUS,
    fiat_p192_montgomery_domain_field_element,
    fiat_p192_from_montgomery,
    fiat_p192_to_montgomery,
    fiat_p192_add,
    fiat_p192_sub,
    fiat_p192_mul,
    fiat_p192_opp,
    fiat_p192_square
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
            U192::LIMBS,
            Limb,
            fiat_p192_from_montgomery,
            fiat_p192_mul,
            fiat_p192_opp,
            fiat_p192_divstep_precomp,
            fiat_p192_divstep,
            fiat_p192_msat,
            fiat_p192_selectznz,
        );

        Self(U192::from_words(words))
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
    const NUM_BITS: u32 = 192;
    const CAPACITY: u32 = 191;
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
