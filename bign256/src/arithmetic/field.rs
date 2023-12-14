//! Field arithmetic modulo p = 2^{256} − 189
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
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects,
    clippy::should_implement_trait,
    clippy::suspicious_op_assign_impl,
    clippy::unused_unit,
    clippy::unnecessary_cast,
    clippy::too_many_arguments,
    clippy::identity_op,
    rustdoc::bare_urls
)]

#[cfg_attr(target_pointer_width = "32", path = "field/bign256_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/bign256_64.rs")]
mod field_impl;

use self::field_impl::*;
use crate::{BignP256, FieldBytes, U256};
use core::{
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, Neg, SubAssign},
};

use elliptic_curve::{
    bigint::Limb,
    ff::PrimeField,
    ops::Invert,
    subtle::{Choice, ConstantTimeEq, CtOption},
};
use primeorder::impl_bernstein_yang_invert;

/// Constant representing the modulus
/// p = 2^{256} − 189
pub(crate) const MODULUS: U256 =
    U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43");

/// Element of the bign-256 base field used for curve coordinates.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(super) U256);

primeorder::impl_mont_field_element!(
    BignP256,
    FieldElement,
    FieldBytes,
    U256,
    MODULUS,
    fiat_bign256_montgomery_domain_field_element,
    fiat_bign256_from_montgomery,
    fiat_bign256_to_montgomery,
    fiat_bign256_add,
    fiat_bign256_sub,
    fiat_bign256_mul,
    fiat_bign256_opp,
    fiat_bign256_square
);

impl FieldElement {
    /// Compute [`FieldElement`] inversion: `1 / self`.
    pub fn invert(&self) -> CtOption<Self> {
        CtOption::new(self.invert_unchecked(), !self.is_zero())
    }

    /// Returns the multiplicative inverse of self.
    ///
    /// Does not check that self is non-zero.
    const fn invert_unchecked(&self) -> Self {
        let words = impl_bernstein_yang_invert!(
            self.0.as_words(),
            Self::ONE.0.to_words(),
            256,
            U256::LIMBS,
            Limb,
            fiat_bign256_from_montgomery,
            fiat_bign256_mul,
            fiat_bign256_opp,
            fiat_bign256_divstep_precomp,
            fiat_bign256_divstep,
            fiat_bign256_msat,
            fiat_bign256_selectznz,
        );
        Self(U256::from_words(words))
    }

    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Because p ≡ 3 mod 4, sqrt can be done with only one
        // exponentiation via the computation of self^((p + 1) // 4) (mod p).
        let sqrt = self.pow_vartime(&[
            0xffffffffffffffd1,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x3fffffffffffffff,
        ]);
        CtOption::new(sqrt, (sqrt * sqrt).ct_eq(self))
    }
}

impl PrimeField for FieldElement {
    type Repr = FieldBytes;

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

    const MODULUS: &'static str =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43";
    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(2);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self =
        Self::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff42");
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    const DELTA: Self = Self::from_u64(4);
}

impl Invert for FieldElement {
    type Output = CtOption<Self>;

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }
}

#[cfg(test)]
mod tests {
    use super::FieldElement;
    use elliptic_curve::ff::PrimeField;
    use primeorder::{
        impl_field_identity_tests, impl_field_invert_tests, impl_field_sqrt_tests,
        impl_primefield_tests,
    };

    // t = (modulus - 1) >> S
    const T: [u64; 4] = [
        0xffffffffffffffa1,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x7fffffffffffffff,
    ];

    impl_field_identity_tests!(FieldElement);
    impl_field_invert_tests!(FieldElement);
    impl_field_sqrt_tests!(FieldElement);
    impl_primefield_tests!(FieldElement, T);
}
