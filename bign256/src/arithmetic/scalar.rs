//! bign-curve256v1 scalar field elements.

#![allow(clippy::unusual_byte_groupings)]

#[cfg_attr(target_pointer_width = "32", path = "scalar/bign256_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/bign256_scalar_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::too_many_arguments,
    clippy::unnecessary_cast
)]
mod scalar_impl;

use self::scalar_impl::*;
use crate::{BignP256, FieldBytes, FieldBytesEncoding, SecretKey, Uint, ORDER_HEX};
use core::{
    iter::{Product, Sum},
    ops::{AddAssign, MulAssign, Neg, Shr, ShrAssign, SubAssign},
};
use elliptic_curve::{
    bigint::Limb,
    ff::PrimeField,
    ops::{Invert, Reduce},
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption},
    Curve as _, Error, Result, ScalarPrimitive,
};
use primeorder::impl_bernstein_yang_invert;

#[cfg(feature = "bits")]
use {crate::ScalarBits, elliptic_curve::group::ff::PrimeFieldBits};

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

#[cfg(doc)]
use core::ops::{Add, Mul, Sub};

/// Scalars are elements in the finite field modulo `n`.
///
/// # Trait impls
///
/// Much of the important functionality of scalars is provided by traits from
/// the [`ff`](https://docs.rs/ff/) crate, which is re-exported as
/// `bign256::elliptic_curve::ff`:
///
/// - [`Field`](https://docs.rs/ff/latest/ff/trait.Field.html) -
///   represents elements of finite fields and provides:
///   - [`Field::random`](https://docs.rs/ff/latest/ff/trait.Field.html#tymethod.random) -
///     generate a random scalar
///   - `double`, `square`, and `invert` operations
///   - Bounds for [`Add`], [`Sub`], [`Mul`], and [`Neg`] (as well as `*Assign` equivalents)
///   - Bounds for [`ConditionallySelectable`] from the `subtle` crate
/// - [`PrimeField`](https://docs.rs/ff/latest/ff/trait.PrimeField.html) -
///   represents elements of prime fields and provides:
///   - `from_repr`/`to_repr` for converting field elements from/to big integers.
///   - `multiplicative_generator` and `root_of_unity` constants.
/// - [`PrimeFieldBits`](https://docs.rs/ff/latest/ff/trait.PrimeFieldBits.html) -
///   operations over field elements represented as bits (requires `bits` feature)
///
/// Please see the documentation for the relevant traits for more information.
#[derive(Clone, Copy, Debug, PartialOrd, Ord)]
pub struct Scalar(Uint);

primeorder::impl_mont_field_element!(
    BignP256,
    Scalar,
    FieldBytes,
    Uint,
    BignP256::ORDER,
    fiat_bign256_scalar_montgomery_domain_field_element,
    fiat_bign256_scalar_from_montgomery,
    fiat_bign256_scalar_to_montgomery,
    fiat_bign256_scalar_add,
    fiat_bign256_scalar_sub,
    fiat_bign256_scalar_mul,
    fiat_bign256_scalar_opp,
    fiat_bign256_scalar_square
);

impl Scalar {
    /// Compute [`Scalar`] inversion: `1 / self`.
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
            fiat_bign256_scalar_from_montgomery,
            fiat_bign256_scalar_mul,
            fiat_bign256_scalar_opp,
            fiat_bign256_scalar_divstep_precomp,
            fiat_bign256_scalar_divstep,
            fiat_bign256_scalar_msat,
            fiat_bign256_scalar_selectznz,
        );
        Self(Uint::from_words(words))
    }

    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        let sqrt =
            {
                let t0 = self;
                let t1 = t0.square();
                let t2 = t1.square();
                let t3 = t2 * t0;
                let t4 = t3.square();
                let t5 = t4 * t0;
                let t6 = t4 * t1;
                let t7 = t6.square();
                let t8 = t7 * t6;
                let t9 = t8.square();
                let t11 = t9 * t5;
                let t12 = t11.square();
                let t13 = t12.square();
                let t14 = t13 * t6;
                let t15 = t14 * t11;
                let t16 = t15.square();
                let t17 = t16 * t15;
                let t23 = t17.sqn(5);
                let t24 = t23 * t17;
                let t25 = t24 * t14;
                let t27 = t25.sqn(2);
                let t28 = t27 * t15;
                let t29 = t28 * t25;
                let t31 = t29.sqn(2);
                let t32 = t31 * t28;
                let t34 = t32.sqn(2);
                let t35 = t34 * t32;
                let t36 = t35 * t29;
                let t37 = t36.square();
                let t38 = t37 * t32;
                let t39 = t38.square();
                let t40 = t39 * t38;
                let t43 = t39.sqn(3);
                let t44 = t43 * t40;
                let t45 = t44 * t36;
                let t46 = t45.square();
                let t47 = t46 * t45;
                let t48 = t47.square();
                let t49 = t48 * t45;
                let t50 = t49.square();
                let t52 = t50 * t38;
                let t53 = t52 * t45;
                let t54 = t53.square();
                let t55 = t54 * t53;
                let t56 = t55.square();
                let t58 = t56 * t52;
                let t59 = t58 * t53;
                let t60 = t59 * t58;
                let t62 = t60.sqn(2);
                let t63 = t62 * t59;
                let t64 = t63 * t60;
                let t65 = t64 * t63;
                let t66 = t65 * t64;
                let t67 = t66 * t65;
                let t68 = t67.square();
                let t69 = t68 * t67;
                let t70 = t69.square();
                let t72 = t70 * t66;
                let t73 = t72 * t67;
                let t74 = t73.square();
                let t75 = t74 * t73;
                let t76 = t75 * t72;
                let t78 = t76.sqn(2);
                let t79 = t78 * t73;
                let t80 = t79.square();
                let t81 = t80 * t79;
                let t82 = t81 * t76;
                let t83 = t82.square();
                let t84 = t83 * t79;
                let t86 = t84.sqn(2);
                let t87 = t86 * t82;
                let t88 = t87 * t84;
                let t89 = t88.square();
                let t90 = t89 * t88;
                let t91 = t90 * t87;
                let t92 = t91 * t88;
                let t93 = t92.square();
                let t94 = t93 * t91;
                let t95 = t94 * t92;
                let t96 = t95 * t94;
                let t98 = t96.sqn(2);
                let t99 = t98 * t96;
                let t100 = t99 * t95;
                let t101 = t100 * t96;
                let t103 = t101.sqn(2);
                let t104 = t103 * t101;
                let t105 = t104.square();
                let t107 = t105 * t100;
                let t109 = t107.sqn(2);
                let t110 = t109 * t101;
                let t111 = t110.square();
                let t112 = t111 * t110;
                let t113 = t112 * t107;
                let t114 = t113.square();
                let t115 = t114.square();
                let t117 = t115.square();
                let t118 = t117.square();
                let t119 = t118 * t114;
                let t120 = t119 * t110;
                let t121 = t120.square();
                let t122 = t121 * t113;
                let t123 = t122 * t120;
                let t124 = t123.square();
                let t125 = t124.square();
                let t126 = t125 * t123;
                let t127 = t126 * t122;
                let t128 = t127 * t123;
                let t129 = t128.square();
                let t130 = t129 * t127;
                let t131 = t130.square();
                let t132 = t131 * t130;
                let t133 = t132.square();
                let t135 = t133 * t128;
                let t136 = t135.square();
                let t137 = t136.square();
                let t139 = t137.square();
                let t140 = t139.square();
                let t141 = t140 * t136;
                let t142 = t141 * t130;
                let t143 = t142.square();
                let t144 = t143.square();
                let t145 = t144 * t142;
                let t146 = t145 * t135;
                let t147 = t146 * t142;
                let t148 = t147.square();
                let t149 = t148.square();
                let t150 = t149 * t147;
                let t151 = t150 * t146;
                let t152 = t151.square();
                let t153 = t152 * t147;
                let t154 = t153 * t151;
                let t155 = t154.square();
                let t156 = t155.square();
                let t157 = t156 * t155;
                let t158 = t157.square();
                let t160 = t158 * t154;
                let t161 = t160.square();
                let t162 = t161.square();
                let t163 = t162 * t155;
                let t164 = t163.square();
                let t165 = t164.square();
                let t166 = t165.square();
                let t167 = t166.square();
                let t169 = t167 * t153;
                let t170 = t169.square();
                let t171 = t170 * t169;
                let t172 = t171.square();
                let t174 = t172 * t154;
                let t175 = t174 * t169;
                let t176 = t175 * t174;
                let t177 = t176.square();
                let t178 = t177.square();
                let t179 = t178 * t176;
                let t180 = t179.square();
                let t182 = t180 * t175;
                let t183 = t182.square();
                let t184 = t183 * t182;
                let t185 = t184.square();
                let t187 = t185.square();
                let t188 = t187 * t182;
                let t189 = t188 * t176;
                let t190 = t189.square();
                let t191 = t190 * t182;
                let t192 = t191.square();
                let t193 = t192.square();
                let t194 = t193 * t189;
                let t195 = t194.square();
                let t196 = t195 * t191;
                let t197 = t196 * t194;
                let t198 = t197 * t196;
                let t199 = t198.square();
                let t200 = t199 * t198;
                let t201 = t200.square();
                let t203 = t201 * t197;
                let t204 = t203 * t198;
                let t205 = t204.square();
                let t206 = t205.square();
                let t207 = t206 * t204;
                let t208 = t207 * t203;
                let t209 = t208.square();
                let t210 = t209 * t204;
                let t211 = t210.square();
                let t212 = t211 * t208;
                let t213 = t212 * t210;
                let t214 = t213.square();
                let t215 = t214.square();
                let t216 = t215 * t212;
                let t342 = t216.sqn(126);
                t342 * t213
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

    /// Right shifts the scalar.
    ///
    /// Note: not constant-time with respect to the `shift` parameter.
    pub const fn shr_vartime(&self, shift: usize) -> Scalar {
        Self(self.0.shr_vartime(shift))
    }
}

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = Uint;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl Invert for Scalar {
    type Output = CtOption<Self>;

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: Uint = BignP256::ORDER.shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl Shr<usize> for Scalar {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        self.shr_vartime(rhs)
    }
}

impl Shr<usize> for &Scalar {
    type Output = Scalar;

    fn shr(self, rhs: usize) -> Self::Output {
        self.shr_vartime(rhs)
    }
}

impl ShrAssign<usize> for Scalar {
    fn shr_assign(&mut self, rhs: usize) {
        *self = *self >> rhs;
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        Self::from_bytes(&repr)
    }

    fn to_repr(&self) -> Self::Repr {
        self.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        self.is_odd()
    }

    const MODULUS: &'static str = ORDER_HEX;
    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(3);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self =
        Self::from_hex("ffffffffffffffffffffffffffffffffd95c8ed60dfb4dfc7e5abf99263d6606");
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    const DELTA: Self = Self::from_u64(9);
}

#[cfg(feature = "bits")]
impl PrimeFieldBits for Scalar {
    type ReprBits = fiat_bign256_scalar_montgomery_domain_field_element;

    fn to_le_bits(&self) -> ScalarBits {
        self.to_canonical().to_words().into()
    }

    fn char_le_bits() -> ScalarBits {
        BignP256::ORDER.to_words().into()
    }
}

impl Reduce<Uint> for Scalar {
    type Bytes = FieldBytes;

    fn reduce(w: Uint) -> Self {
        let (r, underflow) = w.sbb(&BignP256::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(Uint::conditional_select(&w, &r, !underflow))
    }

    #[inline]
    fn reduce_bytes(bytes: &FieldBytes) -> Self {
        let w = <Uint as FieldBytesEncoding<BignP256>>::decode_field_bytes(bytes);
        Self::reduce(w)
    }
}

impl From<ScalarPrimitive<BignP256>> for Scalar {
    fn from(w: ScalarPrimitive<BignP256>) -> Self {
        Scalar::from(&w)
    }
}

impl From<&ScalarPrimitive<BignP256>> for Scalar {
    fn from(w: &ScalarPrimitive<BignP256>) -> Scalar {
        Scalar::from_uint_unchecked(*w.as_uint())
    }
}

impl From<Scalar> for ScalarPrimitive<BignP256> {
    fn from(scalar: Scalar) -> ScalarPrimitive<BignP256> {
        ScalarPrimitive::from(&scalar)
    }
}

impl From<&Scalar> for ScalarPrimitive<BignP256> {
    fn from(scalar: &Scalar) -> ScalarPrimitive<BignP256> {
        ScalarPrimitive::new(scalar.into()).unwrap()
    }
}

impl From<Scalar> for FieldBytes {
    fn from(scalar: Scalar) -> Self {
        scalar.to_repr()
    }
}

impl From<&Scalar> for FieldBytes {
    fn from(scalar: &Scalar) -> Self {
        scalar.to_repr()
    }
}

impl From<Scalar> for Uint {
    fn from(scalar: Scalar) -> Uint {
        Uint::from(&scalar)
    }
}

impl From<&Scalar> for Uint {
    fn from(scalar: &Scalar) -> Uint {
        scalar.to_canonical()
    }
}

impl From<&SecretKey> for Scalar {
    fn from(secret_key: &SecretKey) -> Scalar {
        *secret_key.to_nonzero_scalar()
    }
}

impl TryFrom<Uint> for Scalar {
    type Error = Error;

    fn try_from(w: Uint) -> Result<Self> {
        Option::from(Self::from_uint(w)).ok_or(Error)
    }
}

#[cfg(test)]
mod tests {
    use super::Scalar;
    use elliptic_curve::ff::PrimeField;
    use primeorder::{impl_field_identity_tests, impl_field_invert_tests, impl_field_sqrt_tests, impl_primefield_tests};

    // t = (modulus - 1) >> S
    const T: [u64; 4] = [
        0x3f2d5fcc931eb303,
        0xecae476b06fda6fe,
        0xffffffffffffffff,
        0x7fffffffffffffff,
    ];

    impl_field_identity_tests!(Scalar);
    impl_field_invert_tests!(Scalar);
    impl_field_sqrt_tests!(Scalar);
    impl_primefield_tests!(Scalar, T);
}
