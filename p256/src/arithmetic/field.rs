//! Field arithmetic modulo p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1

#![allow(clippy::assign_op_pattern, clippy::op_ref)]

#[cfg_attr(target_pointer_width = "32", path = "field/field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/field64.rs")]
mod field_impl;

use crate::{FieldBytes, NistP256};
use core::ops::Mul;
use elliptic_curve::{
    FieldBytesEncoding,
    bigint::U256,
    ff::PrimeField,
    subtle::{Choice, ConstantTimeEq, CtOption},
};

const MODULUS_HEX: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

/// Constant representing the modulus
/// p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1
pub const MODULUS: U256 = U256::from_be_hex(MODULUS_HEX);

/// R^2 = 2^512 mod p
const R2: FieldElement = FieldElement(U256::from_be_hex(
    "00000004fffffffdfffffffffffffffefffffffbffffffff0000000000000003",
));

/// An element in the finite field modulo p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1.
///
/// The internal representation is in little-endian order. Elements are always in
/// Montgomery form; i.e., FieldElement(a) = aR mod p, with R = 2^256.
#[derive(Clone, Copy)]
pub struct FieldElement(pub(crate) U256);

primefield::field_element_type!(
    FieldElement,
    FieldBytes,
    U256,
    MODULUS,
    FieldBytesEncoding::<NistP256>::decode_field_bytes,
    FieldBytesEncoding::<NistP256>::encode_field_bytes
);

impl FieldElement {
    /// Decode [`FieldElement`] from [`U256`] converting it into Montgomery form.
    ///
    /// Does *not* perform a check that the field element does not overflow the modulus.
    ///
    /// Used incorrectly this can lead to invalid results!
    pub(crate) const fn from_uint_unchecked(w: U256) -> Self {
        Self(w).to_montgomery()
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
    pub(crate) const fn to_canonical(self) -> U256 {
        field_impl::to_canonical(self.0)
    }

    /// Translate a field element into the Montgomery domain.
    #[inline]
    pub(crate) const fn to_montgomery(self) -> Self {
        Self::multiply(&self, &R2)
    }

    /// Returns self * rhs mod p
    pub const fn multiply(&self, rhs: &Self) -> Self {
        let (lo, hi): (U256, U256) = self.0.widening_mul(&rhs.0);
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
        Self::from_bytes(&bytes)
    }

    fn to_repr(&self) -> FieldBytes {
        self.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        self.is_odd()
    }
}

#[cfg(test)]
mod tests {
    use super::FieldElement;
    use crate::{FieldBytes, U256, test_vectors::field::DBL_TEST_VECTORS};

    #[cfg(target_pointer_width = "64")]
    use proptest::{num::u64::ANY, prelude::*};

    primefield::test_primefield!(FieldElement, U256);

    #[test]
    fn from_bytes() {
        assert_eq!(
            FieldElement::from_bytes(&FieldBytes::default()).unwrap(),
            FieldElement::ZERO
        );
        assert_eq!(
            FieldElement::from_bytes(
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 1
                ]
                .as_ref()
            )
            .unwrap(),
            FieldElement::ONE
        );
        assert!(bool::from(
            FieldElement::from_bytes([0xff; 32].as_ref()).is_none()
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
        for item in DBL_TEST_VECTORS {
            assert_eq!(r.to_bytes().as_slice(), item);
            r = r + &r;
        }
    }

    #[test]
    fn repeated_double() {
        let mut r = FieldElement::ONE;
        for item in DBL_TEST_VECTORS {
            assert_eq!(r.to_bytes().as_slice(), item);
            r = r.double();
        }
    }

    #[test]
    fn repeated_mul() {
        let mut r = FieldElement::ONE;
        let two = r + &r;
        for item in DBL_TEST_VECTORS {
            assert_eq!(r.to_bytes().as_slice(), item);
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
