//! Field arithmetic modulo p = 2^{224} − 2^{96} + 1
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

#[cfg_attr(target_pointer_width = "32", path = "field/p224_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/p224_64.rs")]
mod field_impl;

use self::field_impl::*;
use crate::{FieldBytes, NistP224, Uint};
use core::{
    fmt::{self, Debug},
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, Neg, SubAssign},
};
use elliptic_curve::ops::Invert;
use elliptic_curve::{
    ff::PrimeField,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
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
#[derive(Clone, Copy)]
pub struct FieldElement(pub(super) Uint);

primeorder::impl_mont_field_element!(
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
        CtOption::new(self.invert_unchecked(), !self.is_zero())
    }

    /// Returns the multiplicative inverse of self.
    ///
    /// Does not check that self is non-zero.
    // TODO(tarcieri): double check this is faster than Bernstein-Yang
    const fn invert_unchecked(&self) -> Self {
        // Adapted from addchain: github.com/mmcloughlin/addchain
        let z = self.square();
        let t0 = self.multiply(&z);
        let z = t0.square();
        let z = self.multiply(&z);
        let t1 = z.sqn(3);
        let t1 = z.multiply(&t1);
        let t2 = t1.sqn(6);
        let t1 = t1.multiply(&t2);
        let t1 = t1.sqn(2);
        let t0 = t0.multiply(&t1);
        let t1 = t0.sqn(3);
        let z = z.multiply(&t1);
        let t1 = z.sqn(14);
        let t0 = t0.multiply(&t1);
        let t1 = t0.sqn(17);
        let z = z.multiply(&t1);
        let t1 = z.sqn(48);
        let z = z.multiply(&t1);
        let t1 = z.sqn(31);
        let t0 = t0.multiply(&t1);
        let t0 = t0.sqn(97);
        z.multiply(&t0)
    }

    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        let t0 = self;
        let t1 = t0.square();
        let t2 = t1 * t0;
        let t3 = t2.square();
        let t4 = t3 * t0;
        let t5 = t4.square();
        let t6 = t5 * t0;
        let t7 = t6.square();
        let t8 = t7.square();
        let t9 = t8.square();
        let t10 = t9 * t4;
        let t11 = t10.square();
        let t12 = t11 * t0;
        let t13 = t12.square();
        let t14 = t13.square();
        let t15 = t14.square();
        let t16 = t15.square();
        let t17 = t16.square();
        let t18 = t17.square();
        let t19 = t18.square();
        let t20 = t19 * t10;
        let t21 = t20.square();
        let t22 = t21 * t0;
        let t23 = t22.square();
        let t24 = t23.square();
        let t25 = t24.square();
        let t26 = t25.square();
        let t27 = t26.square();
        let t28 = t27.square();
        let t29 = t28.square();
        let t30 = t29.square();
        let t31 = t30.square();
        let t32 = t31.square();
        let t33 = t32.square();
        let t34 = t33.square();
        let t35 = t34.square();
        let t36 = t35.square();
        let t37 = t36.square();
        let t38 = t37 * t20;
        let t39 = t38.square();
        let t40 = t39 * t0;
        let t41 = t40.square();
        let t42 = t41.square();
        let t43 = t42.square();
        let t44 = t43.square();
        let t45 = t44.square();
        let t46 = t45.square();
        let t47 = t46.square();
        let t48 = t47.square();
        let t49 = t48.square();
        let t50 = t49.square();
        let t51 = t50.square();
        let t52 = t51.square();
        let t53 = t52.square();
        let t54 = t53.square();
        let t55 = t54.square();
        let t56 = t55.square();
        let t57 = t56.square();
        let t58 = t57.square();
        let t59 = t58.square();
        let t60 = t59.square();
        let t61 = t60.square();
        let t62 = t61.square();
        let t63 = t62.square();
        let t64 = t63.square();
        let t65 = t64.square();
        let t66 = t65.square();
        let t67 = t66.square();
        let t68 = t67.square();
        let t69 = t68.square();
        let t70 = t69.square();
        let t71 = t70.square();
        let t72 = t71 * t38;
        let t73 = t72.square();
        let t74 = t73 * t0;
        let t75 = t74.square();
        let t76 = t75.square();
        let t77 = t76.square();
        let t78 = t77.square();
        let t79 = t78.square();
        let t80 = t79.square();
        let t81 = t80.square();
        let t82 = t81.square();
        let t83 = t82.square();
        let t84 = t83.square();
        let t85 = t84.square();
        let t86 = t85.square();
        let t87 = t86.square();
        let t88 = t87.square();
        let t89 = t88.square();
        let t90 = t89.square();
        let t91 = t90.square();
        let t92 = t91.square();
        let t93 = t92.square();
        let t94 = t93.square();
        let t95 = t94.square();
        let t96 = t95.square();
        let t97 = t96.square();
        let t98 = t97.square();
        let t99 = t98.square();
        let t100 = t99.square();
        let t101 = t100.square();
        let t102 = t101.square();
        let t103 = t102.square();
        let t104 = t103.square();
        let t105 = t104.square();
        let t106 = t105.square();
        let t107 = t106.square();
        let t108 = t107.square();
        let t109 = t108.square();
        let t110 = t109.square();
        let t111 = t110.square();
        let t112 = t111.square();
        let t113 = t112.square();
        let t114 = t113.square();
        let t115 = t114.square();
        let t116 = t115.square();
        let t117 = t116.square();
        let t118 = t117.square();
        let t119 = t118.square();
        let t120 = t119.square();
        let t121 = t120.square();
        let t122 = t121.square();
        let t123 = t122.square();
        let t124 = t123.square();
        let t125 = t124.square();
        let t126 = t125.square();
        let t127 = t126.square();
        let t128 = t127.square();
        let t129 = t128.square();
        let t130 = t129.square();
        let t131 = t130.square();
        let t132 = t131.square();
        let t133 = t132.square();
        let t134 = t133.square();
        let t135 = t134.square();
        let t136 = t135.square();
        let t137 = t136.square();
        let w = t137 * t72;

        let mut v = Self::S;
        let mut x = *self * w;
        let mut b = x * w;
        let mut z = Self::ROOT_OF_UNITY;

        for max_v in (1..=Self::S).rev() {
            let mut k = 1;
            let mut tmp = b.square();
            let mut j_less_than_v = Choice::from(1);

            for j in 2..max_v {
                let tmp_is_one = tmp.ct_eq(&Self::ONE);
                let squared = Self::conditional_select(&tmp, &z, tmp_is_one).square();
                tmp = Self::conditional_select(&squared, &tmp, tmp_is_one);
                let new_z = Self::conditional_select(&z, &squared, tmp_is_one);
                j_less_than_v &= !j.ct_eq(&v);
                k = u32::conditional_select(&j, &k, tmp_is_one);
                z = Self::conditional_select(&z, &new_z, j_less_than_v);
            }

            let result = x * z;
            x = Self::conditional_select(&result, &x, b.ct_eq(&Self::ONE));
            z = z.square();
            b *= &z;
            v = k;
        }

        CtOption::new(x, x.square().ct_eq(self))
    }

    /// Returns self^(2^n) mod p
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

    const MODULUS: &'static str = MODULUS_HEX;
    const NUM_BITS: u32 = 224;
    const CAPACITY: u32 = 223;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(22);
    const S: u32 = 96;
    #[cfg(target_pointer_width = "32")]
    const ROOT_OF_UNITY: Self =
        Self::from_hex("395e40142de25856b7e38879fc315d7e6f6de3c1aa72e8c906610583");
    #[cfg(target_pointer_width = "64")]
    const ROOT_OF_UNITY: Self =
        Self::from_hex("00000000395e40142de25856b7e38879fc315d7e6f6de3c1aa72e8c906610583");
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    #[cfg(target_pointer_width = "32")]
    const DELTA: Self = Self::from_hex("697b16135c4a62fca5c4f35ea6d5784cf3808e775aad34ec3d046867");
    #[cfg(target_pointer_width = "64")]
    const DELTA: Self =
        Self::from_hex("00000000697b16135c4a62fca5c4f35ea6d5784cf3808e775aad34ec3d046867");

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

impl Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement(0x{:X})", &self.0)
    }
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

    /// t = (modulus - 1) >> S
    const T: [u64; 4] = [
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x0000000000000000,
        0x0000000000000000,
    ];

    impl_field_identity_tests!(FieldElement);
    impl_field_invert_tests!(FieldElement);
    impl_field_sqrt_tests!(FieldElement);
    impl_primefield_tests!(FieldElement, T);
}
