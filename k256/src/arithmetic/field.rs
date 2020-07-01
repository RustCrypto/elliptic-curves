//! Field arithmetic modulo p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1

use core::ops::{Add, AddAssign, Mul, MulAssign};
use elliptic_curve::subtle::{ConstantTimeEq, CtOption};

#[cfg(feature = "rand")]
use elliptic_curve::rand_core::{CryptoRng, RngCore};


#[cfg(feature = "field-5x52")]
pub use super::field_5x52::{FieldElement};


impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        FieldElement::zero()
    }
}


impl FieldElement {

    /// Returns the multiplicative inverse of self, if self is non-zero.
    pub fn invert(&self) -> CtOption<Self> {
        // The binary representation of (p - 2) has 5 blocks of 1s, with lengths in
        // { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
        // [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]

        let mut x2 = self.square();
        x2 = x2.mul(self);

        let mut x3 = x2.square();
        x3 = x3.mul(self);

        let mut x6 = x3;
        for _j in 0..3 { x6 = x6.square(); }
        x6 = x6.mul(&x3);

        let mut x9 = x6;
        for _j in 0..3 { x9 = x9.square(); }
        x9 = x9.mul(&x3);

        let mut x11 = x9;
        for _j in 0..2 { x11 = x11.square(); }
        x11 = x11.mul(&x2);

        let mut x22 = x11;
        for _j in 0..11 { x22 = x22.square(); }
        x22 = x22.mul(&x11);

        let mut x44 = x22;
        for _j in 0..22 { x44 = x44.square(); }
        x44 = x44.mul(&x22);

        let mut x88 = x44;
        for _j in 0..44 { x88 = x88.square(); }
        x88 = x88.mul(&x44);

        let mut x176 = x88;
        for _j in 0..88 { x176 = x176.square(); }
        x176 = x176.mul(&x88);

        let mut x220 = x176;
        for _j in 0..44 { x220 = x220.square(); }
        x220 = x220.mul(&x44);

        let mut x223 = x220;
        for _j in 0..3 { x223 = x223.square(); }
        x223 = x223.mul(&x3);

        // The final result is then assembled using a sliding window over the blocks.

        let mut t1 = x223;
        for _j in 0..23 { t1 = t1.square(); }
        t1 = t1.mul(&x22);
        for _j in 0..5 { t1 = t1.square(); }
        t1 = t1.mul(self);
        for _j in 0..3 { t1 = t1.square(); }
        t1 = t1.mul(&x2);
        for _j in 0..2 { t1 = t1.square(); }
        t1 = t1.mul(self);

        CtOption::new(t1, !self.is_zero())
    }

    /// Returns the square root of self mod p, or `None` if no square root exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        /*
        Given that p is congruent to 3 mod 4, we can compute the square root of
        a mod p as the (p+1)/4'th power of a.

        As (p+1)/4 is an even number, it will have the same result for a and for
        (-a). Only one of these two numbers actually has a square root however,
        so we test at the end by squaring and comparing to the input.
        Also because (p+1)/4 is an even number, the computed square root is
        itself always a square (a ** ((p+1)/4) is the square of a ** ((p+1)/8)).
        */

        // The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
        // { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
        // 1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]

        let mut x2 = self.square();
        x2 = x2.mul(self);

        let mut x3 = x2.square();
        x3 = x3.mul(self);

        let mut x6 = x3;
        for _j in 0..3 { x6 = x6.square(); }
        x6 = x6.mul(&x3);

        let mut x9 = x6;
        for _j in 0..3 { x9 = x9.square(); }
        x9 = x9.mul(&x3);

        let mut x11 = x9;
        for _j in 0..2 { x11 = x11.square(); }
        x11 = x11.mul(&x2);

        let mut x22 = x11;
        for _j in 0..11 { x22 = x22.square(); }
        x22 = x22.mul(&x11);

        let mut x44 = x22;
        for _j in 0..22 { x44 = x44.square(); }
        x44 = x44.mul(&x22);

        let mut x88 = x44;
        for _j in 0..44 { x88 = x88.square(); }
        x88 = x88.mul(&x44);

        let mut x176 = x88;
        for _j in 0..88 { x176 = x176.square(); }
        x176 = x176.mul(&x88);

        let mut x220 = x176;
        for _j in 0..44 { x220 = x220.square(); }
        x220 = x220.mul(&x44);

        let mut x223 = x220;
        for _j in 0..3 { x223 = x223.square(); }
        x223 = x223.mul(&x3);

        // The final result is then assembled using a sliding window over the blocks.

        let mut t1 = x223;
        for _j in 0..23 { t1 = t1.square(); }
        t1 = t1.mul(&x22);
        for _j in 0..6 { t1 = t1.square(); }
        t1 = t1.mul(&x2);
        t1 = t1.square();
        let sqrt = t1.square();

        CtOption::new(
            sqrt,
            (&sqrt * &sqrt).normalize().ct_eq(&self.normalize()), // Only return Some if it's the square root.
        )
    }
}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement::add(self, other)
    }
}

impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement::add(&self, other)
    }
}

impl AddAssign<FieldElement> for FieldElement {
    fn add_assign(&mut self, rhs: FieldElement) {
        *self = FieldElement::add(self, &rhs);
    }
}


impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement::mul(self, other)
    }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement::mul(&self, other)
    }
}

impl MulAssign<FieldElement> for FieldElement {
    fn mul_assign(&mut self, rhs: FieldElement) {
        *self = FieldElement::mul(self, &rhs);
    }
}


#[cfg(test)]
mod tests {
    use fiat_crypto::secp256k1_64::{
        fiat_secp256k1_add, fiat_secp256k1_mul, fiat_secp256k1_opp, fiat_secp256k1_square,
        fiat_secp256k1_sub,
    };
    use proptest::{num::u64::ANY, prelude::*};

    use super::FieldElement;
    use crate::test_vectors::field::DBL_TEST_VECTORS;

    #[test]
    fn zero_is_additive_identity() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();
        assert_eq!(zero.add(&zero), zero);
        assert_eq!(one.add(&zero), one);
    }

    #[test]
    fn one_is_multiplicative_identity() {
        let one = FieldElement::one();
        assert_eq!(one.mul(&one), one);
    }

    #[test]
    fn from_bytes() {
        assert_eq!(
            FieldElement::from_bytes([0; 32]).unwrap(),
            FieldElement::zero()
        );
        assert_eq!(
            FieldElement::from_bytes([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ])
            .unwrap(),
            FieldElement::one()
        );
        assert!(bool::from(FieldElement::from_bytes([0xff; 32]).is_none()));
    }

    #[test]
    fn to_bytes() {
        assert_eq!(FieldElement::zero().to_bytes(), [0; 32]);
        assert_eq!(
            FieldElement::one().to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ]
        );
    }

    #[test]
    fn repeated_add() {
        let mut r = FieldElement::one();
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(hex::encode(r.to_bytes()), DBL_TEST_VECTORS[i]);
            r = (r + &r).normalize();
        }
    }

    #[test]
    fn repeated_double() {
        let mut r = FieldElement::one();
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(hex::encode(r.to_bytes()), DBL_TEST_VECTORS[i]);
            r = r.double().normalize();
        }
    }

    #[test]
    fn repeated_mul() {
        let mut r = FieldElement::one();
        let two = r + &r;
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(hex::encode(r.to_bytes()), DBL_TEST_VECTORS[i]);
            r = r * &two;
        }
    }

    #[test]
    fn negation() {
        let two = FieldElement::one().double();
        let neg_two = two.negate(2);
        assert_eq!((two + &neg_two).normalize(), FieldElement::zero());
        assert_eq!(neg_two.negate(3).normalize(), two.normalize());
    }

    #[test]
    fn invert() {
        assert!(bool::from(FieldElement::zero().invert().is_none()));

        let one = FieldElement::one();
        assert_eq!(one.invert().unwrap().normalize(), one);

        let two = one + &one;
        let inv_two = two.invert().unwrap();
        assert_eq!((two * &inv_two).normalize(), one);
    }

    #[test]
    fn sqrt() {
        let one = FieldElement::one();
        let two = one + &one;
        let four = two.square();
        assert_eq!(four.sqrt().unwrap().normalize(), two.normalize());
    }

    proptest! {

        /// These tests fuzz the Field arithmetic implementation against
        /// fiat-crypto.
        /*
        #[test]
        fn mul_with_fiat(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
            b0 in ANY,
            b1 in ANY,
            b2 in ANY,
        ) {
            let mut out: [u64; 4] = [0; 4];
            let a = [a0, a1, a2, 0];
            let b = [b0, b1, b2, 0];
            fiat_secp256k1_mul(&mut out, &a, &b);
            let a_f = FieldElement::from_words(a).unwrap();
            let b_f = FieldElement::from_words(b).unwrap();
            assert_eq!(a_f.mul(&b_f).normalize().to_words(), out);
        }

        #[test]
        fn square_with_fiat(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
        ) {
            let mut out: [u64; 4] = [0; 4];
            let a = [a0, a1, a2, 0];
            fiat_secp256k1_square(&mut out, &a);
            let a_f = FieldElement::from_words(a).unwrap();
            assert_eq!(a_f.square().normalize().to_words(), out);
        }
        */

        #[test]
        fn add_with_fiat(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
            b0 in ANY,
            b1 in ANY,
            b2 in ANY,
        ) {
            let mut out: [u64; 4] = [0; 4];
            let a = [a0, a1, a2, 0];
            let b = [b0, b1, b2, 0];
            fiat_secp256k1_add(&mut out, &a, &b);
            let a_f = FieldElement::from_words(a).unwrap();
            let b_f = FieldElement::from_words(b).unwrap();
            assert_eq!(a_f.add(&b_f).normalize().to_words(), out);
        }

        #[test]
        fn sub_with_fiat(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
            b0 in ANY,
            b1 in ANY,
            b2 in ANY,
        ) {
            let mut out: [u64; 4] = [0; 4];
            let a = [a0, a1, a2, 0];
            let b = [b0, b1, b2, 0];
            fiat_secp256k1_sub(&mut out, &a, &b);
            let a_f = FieldElement::from_words(a).unwrap();
            let b_f = FieldElement::from_words(b).unwrap();
            assert_eq!((a_f + &b_f.negate(1)).to_words(), out);
        }

        #[test]
        fn negate_with_fiat(
            a0 in ANY,
            a1 in ANY,
            a2 in ANY,
        ) {
            let mut out: [u64; 4] = [0; 4];
            let a = [a0, a1, a2, 0];
            fiat_secp256k1_opp(&mut out, &a);
            let a_f = FieldElement::from_words(a).unwrap();
            assert_eq!((a_f.negate(1)).to_words(), out);
        }
    }
}
