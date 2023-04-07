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
    clippy::should_implement_trait,
    clippy::suspicious_op_assign_impl,
    clippy::unused_unit,
    clippy::unnecessary_cast,
    clippy::too_many_arguments,
    clippy::identity_op
)]

#[cfg_attr(target_pointer_width = "32", path = "field/bign256_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/bign256_64.rs")]
mod field_impl;

use self::field_impl::*;
use crate::{BignP256, FieldBytes, Uint};
use core::{
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, Neg, SubAssign},
};
use elliptic_curve::bigint::Limb;
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};
use primeorder::impl_bernstein_yang_invert;

/// Constant representing the modulus
/// p = 2^{256} − 189
pub(crate) const MODULUS: Uint =
    Uint::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43");

/// Element of the bign-256 base field used for curve coordinates.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(super) Uint);

primeorder::impl_mont_field_element!(
    BignP256,
    FieldElement,
    FieldBytes,
    Uint,
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
            Uint::LIMBS,
            Limb,
            fiat_bign256_from_montgomery,
            fiat_bign256_mul,
            fiat_bign256_opp,
            fiat_bign256_divstep_precomp,
            fiat_bign256_divstep,
            fiat_bign256_msat,
            fiat_bign256_selectznz,
        );
        Self(Uint::from_words(words))
    }

    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Adapted code from ff crate
        let sqrt = {
            let t0 = self;
            let t4 = t0.sqn(4);
            let t5 = t4 * t0;
            let t7 = t5.sqn(2);
            let t8 = t7 * t5;
            let t9 = t8.square();
            let t10 = t9 * t5;
            let t12 = t10.square();
            let t13 = t12 * t10;
            let t17 = t13.sqn(4);
            let t18 = t17 * t13;
            let t20 = t18.square();
            let t21 = t20 * t18;
            let t26 = t21.sqn(5);
            let t27 = t26 * t21;
            let t29 = t27.square();
            let t30 = t29.square();
            let t31 = t30.square();
            let t32 = t31 * t30;
            let t34 = t32.square();
            let t35 = t34.square();
            let t36 = t35.square();
            let t37 = t36 * t30;
            let t38 = t37 * t21;
            let t39 = t38.square();
            let t40 = t39 * t38;
            let t41 = t40 * t27;
            let t42 = t41.square();
            let t43 = t42 * t38;
            let t44 = t43.square();
            let t45 = t44 * t43;
            let t46 = t45 * t41;
            let t47 = t46.square();
            let t48 = t47.square();
            let t49 = t48 * t46;
            let t50 = t49.square();
            let t51 = t50 * t46;
            let t52 = t51 * t43;
            let t53 = t52 * t46;
            let t54 = t53.square();
            let t55 = t54.square();
            let t56 = t55 * t52;
            let t78 = t56.sqn(22);
            let t79 = t78 * t53;
            let t80 = t79 * t13;
            let t81 = t80 * t18;
            let t82 = t81 * t80;
            let t83 = t82 * t81;
            let t84 = t83 * t82;
            let t85 = t84 * t83;
            let t86 = t85.square();
            let t87 = t86 * t85;
            let t88 = t87 * t84;
            let t89 = t88.square();
            let t90 = t89 * t85;
            let t91 = t90 * t88;
            let t92 = t91 * t90;
            let t93 = t92 * t91;
            let t152 = t93.sqn(59);
            let t153 = t152 * t92;
            let t154 = t153 * t5;
            let t156 = t154.sqn(2);
            let t157 = t156 * t10;
            let t283 = t157.sqn(126);
            t283 * t154
        };

        CtOption::new(sqrt, (sqrt * sqrt).ct_eq(self))
    }

    #[allow(dead_code)]
    /// Returns self^(2^n) mod p.
    const fn sqn(&self, n: usize) -> Self {
        let mut x = *self;
        let mut i = 0;
        while i < n {
            x = x.square();
            i += 1;
        }
        x
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
