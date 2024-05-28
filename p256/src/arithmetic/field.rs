//! Field arithmetic modulo p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1

#![allow(clippy::assign_op_pattern, clippy::op_ref)]

#[cfg_attr(target_pointer_width = "32", path = "field/field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/field64.rs")]
mod field_impl;

use crate::FieldBytes;
use core::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::ops::Invert;
use elliptic_curve::{
    bigint::{ArrayEncoding, U256, U512},
    ff::{Field, PrimeField},
    rand_core::RngCore,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess, CtOption},
    zeroize::DefaultIsZeroes,
};

const MODULUS_HEX: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

/// Constant representing the modulus
/// p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1
pub const MODULUS: FieldElement = FieldElement(U256::from_be_hex(MODULUS_HEX));

/// R = 2^256 mod p
const R: FieldElement = FieldElement(U256::from_be_hex(
    "00000000fffffffeffffffffffffffffffffffff000000000000000000000001",
));

/// R^2 = 2^512 mod p
const R2: FieldElement = FieldElement(U256::from_be_hex(
    "00000004fffffffdfffffffffffffffefffffffbffffffff0000000000000003",
));

/// An element in the finite field modulo p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1.
///
/// The internal representation is in little-endian order. Elements are always in
/// Montgomery form; i.e., FieldElement(a) = aR mod p, with R = 2^256.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(crate) U256);

impl FieldElement {
    /// Zero element.
    pub const ZERO: Self = FieldElement(U256::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = R;

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: FieldBytes) -> CtOption<Self> {
        Self::from_uint(U256::from_be_byte_array(bytes))
    }

    /// Returns the SEC1 encoding of this field element.
    pub fn to_bytes(self) -> FieldBytes {
        self.to_canonical().0.to_be_byte_array()
    }

    /// Decode [`FieldElement`] from [`U256`], converting it into Montgomery form:
    ///
    /// ```text
    /// w * R^2 * R^-1 mod p = wR mod p
    /// ```
    pub fn from_uint(uint: U256) -> CtOption<Self> {
        let is_some = uint.ct_lt(&MODULUS.0);
        CtOption::new(Self::from_uint_unchecked(uint), is_some)
    }

    /// Convert a `u64` into a [`FieldElement`].
    pub const fn from_u64(w: u64) -> Self {
        Self::from_uint_unchecked(U256::from_u64(w))
    }

    /// Parse a [`FieldElement`] from big endian hex-encoded bytes.
    ///
    /// Does *not* perform a check that the field element does not overflow the order.
    ///
    /// This method is primarily intended for defining internal constants.
    pub(crate) const fn from_hex(hex: &str) -> Self {
        Self::from_uint_unchecked(U256::from_be_hex(hex))
    }

    /// Decode [`FieldElement`] from [`U256`] converting it into Montgomery form.
    ///
    /// Does *not* perform a check that the field element does not overflow the order.
    ///
    /// Used incorrectly this can lead to invalid results!
    pub(crate) const fn from_uint_unchecked(w: U256) -> Self {
        Self(w).to_montgomery()
    }

    /// Determine if this `FieldElement` is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&FieldElement::ZERO)
    }

    /// Determine if this `FieldElement` is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        let bytes = self.to_bytes();
        (bytes[31] & 1).into()
    }

    /// Returns self + rhs mod p
    pub const fn add(&self, rhs: &Self) -> Self {
        Self(field_impl::add(self.0, rhs.0))
    }

    /// Returns 2 * self.
    pub const fn double(&self) -> Self {
        self.add(self)
    }

    /// Returns self - rhs mod p
    pub const fn sub(&self, rhs: &Self) -> Self {
        Self(field_impl::sub(self.0, rhs.0))
    }

    /// Negate element.
    pub const fn neg(&self) -> Self {
        Self::sub(&Self::ZERO, self)
    }

    /// Translate a field element out of the Montgomery domain.
    #[inline]
    pub(crate) const fn to_canonical(self) -> Self {
        Self(field_impl::to_canonical(self.0))
    }

    /// Translate a field element into the Montgomery domain.
    #[inline]
    pub(crate) const fn to_montgomery(self) -> Self {
        Self::multiply(&self, &R2)
    }

    /// Returns self * rhs mod p
    pub const fn multiply(&self, rhs: &Self) -> Self {
        let (lo, hi): (U256, U256) = self.0.split_mul(&rhs.0);
        Self(field_impl::montgomery_reduce(lo, hi))
    }

    /// Returns self * self mod p
    pub const fn square(&self) -> Self {
        // Schoolbook multiplication.
        self.multiply(self)
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

    /// Returns `self^by`, where `by` is a little-endian integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent.** If the exponent
    /// is fixed, this operation is effectively constant time.
    pub fn pow_vartime(&self, by: &[u64; 4]) -> Self {
        let mut res = Self::ONE;
        for e in by.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();

                if ((*e >> i) & 1) == 1 {
                    res = res * self;
                }
            }
        }
        res
    }

    /// Returns the multiplicative inverse of self, if self is non-zero.
    pub fn invert(&self) -> CtOption<Self> {
        CtOption::new(self.invert_unchecked(), !self.is_zero())
    }

    /// Returns the multiplicative inverse of self.
    ///
    /// Does not check that self is non-zero.
    const fn invert_unchecked(&self) -> Self {
        // We need to find b such that b * a ≡ 1 mod p. As we are in a prime
        // field, we can apply Fermat's Little Theorem:
        //
        //    a^p         ≡ a mod p
        //    a^(p-1)     ≡ 1 mod p
        //    a^(p-2) * a ≡ 1 mod p
        //
        // Thus inversion can be implemented with a single exponentiation.
        let t111 = self.multiply(&self.multiply(&self.square()).square());
        let t111111 = t111.multiply(&t111.sqn(3));
        let x15 = t111111.sqn(6).multiply(&t111111).sqn(3).multiply(&t111);
        let x16 = x15.square().multiply(self);
        let i53 = x16.sqn(16).multiply(&x16).sqn(15);
        let x47 = x15.multiply(&i53);
        x47.multiply(&i53.sqn(17).multiply(self).sqn(143).multiply(&x47).sqn(47))
            .sqn(2)
            .multiply(self)
    }

    /// Returns the square root of self mod p, or `None` if no square root exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // We need to find alpha such that alpha^2 = beta mod p. For secp256r1,
        // p ≡ 3 mod 4. By Euler's Criterion, beta^(p-1)/2 ≡ 1 mod p. So:
        //
        //     alpha^2 = beta beta^((p - 1) / 2) mod p ≡ beta^((p + 1) / 2) mod p
        //     alpha = ± beta^((p + 1) / 4) mod p
        //
        // Thus sqrt can be implemented with a single exponentiation.

        let t11 = self.mul(&self.square());
        let t1111 = t11.mul(&t11.sqn(2));
        let t11111111 = t1111.mul(t1111.sqn(4));
        let x16 = t11111111.sqn(8).mul(t11111111);
        let sqrt = x16
            .sqn(16)
            .mul(x16)
            .sqn(32)
            .mul(self)
            .sqn(96)
            .mul(self)
            .sqn(94);

        CtOption::new(
            sqrt,
            (&sqrt * &sqrt).ct_eq(self), // Only return Some if it's the square root.
        )
    }
}

impl Field for FieldElement {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    fn random(mut rng: impl RngCore) -> Self {
        // We reduce a random 512-bit value into a 256-bit field, which results in a
        // negligible bias from the uniform distribution.
        let mut buf = [0; 64];
        rng.fill_bytes(&mut buf);
        let buf = U512::from_be_slice(&buf);
        Self(field_impl::from_bytes_wide(buf))
    }

    #[must_use]
    fn square(&self) -> Self {
        self.square()
    }

    #[must_use]
    fn double(&self) -> Self {
        self.double()
    }

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }

    fn sqrt(&self) -> CtOption<Self> {
        self.sqrt()
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        elliptic_curve::ff::helpers::sqrt_ratio_generic(num, div)
    }
}

impl PrimeField for FieldElement {
    type Repr = FieldBytes;

    const MODULUS: &'static str = MODULUS_HEX;
    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(6);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self =
        Self::from_hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffe");
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    const DELTA: Self = Self::from_u64(36);

    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        Self::from_bytes(bytes)
    }

    fn to_repr(&self) -> FieldBytes {
        self.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        self.is_odd()
    }
}

impl ConditionallySelectable for FieldElement {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(U256::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        FieldElement::ZERO
    }
}

impl DefaultIsZeroes for FieldElement {}

impl Eq for FieldElement {}

impl From<u64> for FieldElement {
    fn from(n: u64) -> FieldElement {
        Self::from_uint_unchecked(U256::from(n))
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Invert for FieldElement {
    type Output = CtOption<Self>;

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }
}

impl Add<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: FieldElement) -> FieldElement {
        FieldElement::add(&self, &other)
    }
}

impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement::add(&self, other)
    }
}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement::add(self, other)
    }
}

impl AddAssign<FieldElement> for FieldElement {
    fn add_assign(&mut self, other: FieldElement) {
        *self = FieldElement::add(self, &other);
    }
}

impl AddAssign<&FieldElement> for FieldElement {
    fn add_assign(&mut self, other: &FieldElement) {
        *self = FieldElement::add(self, other);
    }
}

impl Sub<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: FieldElement) -> FieldElement {
        FieldElement::sub(&self, &other)
    }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        FieldElement::sub(&self, other)
    }
}

impl Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        FieldElement::sub(self, other)
    }
}

impl SubAssign<FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: FieldElement) {
        *self = FieldElement::sub(self, &other);
    }
}

impl SubAssign<&FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: &FieldElement) {
        *self = FieldElement::sub(self, other);
    }
}

impl Mul<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: FieldElement) -> FieldElement {
        FieldElement::multiply(&self, &other)
    }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement::multiply(&self, other)
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement::multiply(self, other)
    }
}

impl MulAssign<FieldElement> for FieldElement {
    fn mul_assign(&mut self, other: FieldElement) {
        *self = FieldElement::multiply(self, &other);
    }
}

impl MulAssign<&FieldElement> for FieldElement {
    fn mul_assign(&mut self, other: &FieldElement) {
        *self = FieldElement::multiply(self, other);
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement::ZERO - &self
    }
}

impl Neg for &FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement::ZERO - self
    }
}

impl Sum for FieldElement {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Add::add).unwrap_or(Self::ZERO)
    }
}

impl<'a> Sum<&'a FieldElement> for FieldElement {
    fn sum<I: Iterator<Item = &'a FieldElement>>(iter: I) -> Self {
        iter.copied().sum()
    }
}

impl Product for FieldElement {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Mul::mul).unwrap_or(Self::ONE)
    }
}

impl<'a> Product<&'a FieldElement> for FieldElement {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.copied().product()
    }
}

#[cfg(test)]
mod tests {
    use super::FieldElement;
    use crate::{test_vectors::field::DBL_TEST_VECTORS, FieldBytes};
    use core::ops::Mul;

    #[cfg(target_pointer_width = "64")]
    use crate::U256;
    #[cfg(target_pointer_width = "64")]
    use proptest::{num::u64::ANY, prelude::*};

    #[test]
    fn zero_is_additive_identity() {
        let zero = FieldElement::ZERO;
        let one = FieldElement::ONE;
        assert_eq!(zero.add(&zero), zero);
        assert_eq!(one.add(&zero), one);
    }

    #[test]
    fn one_is_multiplicative_identity() {
        let one = FieldElement::ONE;
        assert_eq!(one.mul(&one), one);
    }

    #[test]
    fn from_bytes() {
        assert_eq!(
            FieldElement::from_bytes(FieldBytes::default()).unwrap(),
            FieldElement::ZERO
        );
        assert_eq!(
            FieldElement::from_bytes(
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 1
                ]
                .into()
            )
            .unwrap(),
            FieldElement::ONE
        );
        assert!(bool::from(
            FieldElement::from_bytes([0xff; 32].into()).is_none()
        ));
    }

    #[test]
    fn to_bytes() {
        assert_eq!(FieldElement::ZERO.to_bytes(), FieldBytes::default());
        assert_eq!(
            FieldElement::ONE.to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ]
        );
    }

    #[test]
    fn repeated_add() {
        let mut r = FieldElement::ONE;
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(r.to_bytes(), DBL_TEST_VECTORS[i]);
            r = r + &r;
        }
    }

    #[test]
    fn repeated_double() {
        let mut r = FieldElement::ONE;
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(r.to_bytes(), DBL_TEST_VECTORS[i]);
            r = r.double();
        }
    }

    #[test]
    fn repeated_mul() {
        let mut r = FieldElement::ONE;
        let two = r + &r;
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(r.to_bytes(), DBL_TEST_VECTORS[i]);
            r = r * &two;
        }
    }

    #[test]
    fn negation() {
        let two = FieldElement::ONE.double();
        let neg_two = -two;
        assert_eq!(two + &neg_two, FieldElement::ZERO);
        assert_eq!(-neg_two, two);
    }

    #[test]
    fn pow_vartime() {
        let one = FieldElement::ONE;
        let two = one + &one;
        let four = two.square();
        assert_eq!(two.pow_vartime(&[2, 0, 0, 0]), four);
    }

    #[test]
    fn invert() {
        assert!(bool::from(FieldElement::ZERO.invert().is_none()));

        let one = FieldElement::ONE;
        assert_eq!(one.invert().unwrap(), one);

        let two = one + &one;
        let inv_two = two.invert().unwrap();
        assert_eq!(two * &inv_two, one);
    }

    #[test]
    fn sqrt() {
        let one = FieldElement::ONE;
        let two = one + &one;
        let four = two.square();
        assert_eq!(four.sqrt().unwrap(), two);
    }

    #[cfg(target_pointer_width = "64")]
    proptest! {
        /// This checks behaviour well within the field ranges, because it doesn't set the
        /// highest limb.
        #[test]
        fn add_then_sub(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
            b0 in ANY,
            b1 in ANY,
            b2 in ANY,
        ) {
            let a = FieldElement(U256::from_words([a0, a1, a2, 0]));
            let b = FieldElement(U256::from_words([b0, b1, b2, 0]));
            assert_eq!(a.add(&b).sub(&a), b);
        }
    }
}
