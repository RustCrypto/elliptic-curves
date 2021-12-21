//! Field arithmetic modulo p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1

#![allow(clippy::assign_op_pattern, clippy::op_ref)]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_pointer_width = "32")] {
        mod field_10x26;
    } else if #[cfg(target_pointer_width = "64")] {
        mod field_5x52;
    } else {
        compile_error!("unsupported target word size (i.e. target_pointer_width)");
    }
}

cfg_if! {
    if #[cfg(debug_assertions)] {
        mod field_impl;
        use field_impl::FieldElementImpl;
    } else {
        cfg_if! {
            if #[cfg(target_pointer_width = "32")] {
                use field_10x26::FieldElement10x26 as FieldElementImpl;
            } else if #[cfg(target_pointer_width = "64")] {
                use field_5x52::FieldElement5x52 as FieldElementImpl;
            } else {
                compile_error!("unsupported target word size (i.e. target_pointer_width)");
            }
        }
    }
}

use crate::FieldBytes;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    ff::Field,
    rand_core::RngCore,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
};

#[cfg(feature = "hashing")]
use hash2field::FromOkm;

#[cfg(test)]
use num_bigint::{BigUint, ToBigUint};

/// An element in the finite field used for curve coordinates.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(FieldElementImpl);

impl Field for FieldElement {
    fn random(mut rng: impl RngCore) -> Self {
        let mut bytes = FieldBytes::default();

        loop {
            rng.fill_bytes(&mut bytes);
            if let Some(fe) = Self::from_bytes(&bytes).into() {
                return fe;
            }
        }
    }

    fn zero() -> Self {
        Self::ZERO
    }

    fn one() -> Self {
        Self::ONE
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
}

impl FieldElement {
    /// Zero element.
    pub const ZERO: Self = Self(FieldElementImpl::zero());

    /// Multiplicative identity.
    pub const ONE: Self = Self(FieldElementImpl::one());

    /// Determine if this `FieldElement` is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    /// Determine if this `FieldElement` is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    /// Does not check the result for being in the correct range.
    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        Self(FieldElementImpl::from_bytes_unchecked(bytes))
    }

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: &FieldBytes) -> CtOption<Self> {
        FieldElementImpl::from_bytes(bytes).map(Self)
    }

    /// Returns the SEC1 encoding of this field element.
    pub fn to_bytes(self) -> FieldBytes {
        self.0.normalize().to_bytes()
    }

    /// Returns -self, treating it as a value of given magnitude.
    /// The provided magnitude must be equal or greater than the actual magnitude of `self`.
    pub fn negate(&self, magnitude: u32) -> Self {
        Self(self.0.negate(magnitude))
    }

    /// Fully normalizes the field element.
    /// Brings the magnitude to 1 and modulo reduces the value.
    pub fn normalize(&self) -> Self {
        Self(self.0.normalize())
    }

    /// Weakly normalizes the field element.
    /// Brings the magnitude to 1, but does not guarantee the value to be less than the modulus.
    pub fn normalize_weak(&self) -> Self {
        Self(self.0.normalize_weak())
    }

    /// Checks if the field element becomes zero if normalized.
    pub fn normalizes_to_zero(&self) -> Choice {
        self.0.normalizes_to_zero()
    }

    /// Multiplies by a single-limb integer.
    /// Multiplies the magnitude by the same value.
    pub fn mul_single(&self, rhs: u32) -> Self {
        Self(self.0.mul_single(rhs))
    }

    /// Returns 2*self.
    /// Doubles the magnitude.
    pub fn double(&self) -> Self {
        Self(self.0.add(&(self.0)))
    }

    /// Returns self * rhs mod p
    /// Brings the magnitude to 1 (but doesn't normalize the result).
    /// The magnitudes of arguments should be <= 8.
    pub fn mul(&self, rhs: &Self) -> Self {
        Self(self.0.mul(&(rhs.0)))
    }

    /// Returns self * self.
    ///
    /// Brings the magnitude to 1 (but doesn't normalize the result).
    /// The magnitudes of arguments should be <= 8.
    pub fn square(&self) -> Self {
        Self(self.0.square())
    }

    /// Raises the scalar to the power `2^k`
    fn pow2k(&self, k: usize) -> Self {
        let mut x = *self;
        for _j in 0..k {
            x = x.square();
        }
        x
    }

    /// Returns the multiplicative inverse of self, if self is non-zero.
    /// The result has magnitude 1, but is not normalized.
    pub fn invert(&self) -> CtOption<Self> {
        // The binary representation of (p - 2) has 5 blocks of 1s, with lengths in
        // { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
        // [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]

        let x2 = self.pow2k(1).mul(self);
        let x3 = x2.pow2k(1).mul(self);
        let x6 = x3.pow2k(3).mul(&x3);
        let x9 = x6.pow2k(3).mul(&x3);
        let x11 = x9.pow2k(2).mul(&x2);
        let x22 = x11.pow2k(11).mul(&x11);
        let x44 = x22.pow2k(22).mul(&x22);
        let x88 = x44.pow2k(44).mul(&x44);
        let x176 = x88.pow2k(88).mul(&x88);
        let x220 = x176.pow2k(44).mul(&x44);
        let x223 = x220.pow2k(3).mul(&x3);

        // The final result is then assembled using a sliding window over the blocks.
        let res = x223
            .pow2k(23)
            .mul(&x22)
            .pow2k(5)
            .mul(self)
            .pow2k(3)
            .mul(&x2)
            .pow2k(2)
            .mul(self);

        CtOption::new(res, !self.normalizes_to_zero())
    }

    /// Returns the square root of self mod p, or `None` if no square root exists.
    /// The result has magnitude 1, but is not normalized.
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

        let x2 = self.pow2k(1).mul(self);
        let x3 = x2.pow2k(1).mul(self);
        let x6 = x3.pow2k(3).mul(&x3);
        let x9 = x6.pow2k(3).mul(&x3);
        let x11 = x9.pow2k(2).mul(&x2);
        let x22 = x11.pow2k(11).mul(&x11);
        let x44 = x22.pow2k(22).mul(&x22);
        let x88 = x44.pow2k(44).mul(&x44);
        let x176 = x88.pow2k(88).mul(&x88);
        let x220 = x176.pow2k(44).mul(&x44);
        let x223 = x220.pow2k(3).mul(&x3);

        // The final result is then assembled using a sliding window over the blocks.
        let res = x223.pow2k(23).mul(&x22).pow2k(6).mul(&x2).pow2k(2);

        let is_root = (res.mul(&res).negate(1) + self).normalizes_to_zero();

        // Only return Some if it's the square root.
        CtOption::new(res, is_root)
    }

    #[cfg(test)]
    pub fn modulus_as_biguint() -> BigUint {
        Self::one().negate(1).to_biguint().unwrap() + 1.to_biguint().unwrap()
    }

    #[cfg(feature = "hashing")]
    /// Return the parity of the field
    /// 1 == negative
    /// 0 == non-negative
    pub fn sgn0(&self) -> u8 {
        let bytes = self.to_bytes();
        bytes[31] & 1
    }

    /// Hash to field element
    #[cfg(feature = "hashing")]
    pub fn hash<X>(msg: &[u8], dst: &[u8]) -> [Self; 2]
    where
        X: hash2field::ExpandMsg<96>,
    {
        let random_bytes = X::expand_message(msg, dst);
        [
            Self::from_okm(&<[u8; 48]>::try_from(&random_bytes[..48]).unwrap()),
            Self::from_okm(&<[u8; 48]>::try_from(&random_bytes[48..]).unwrap()),
        ]
    }

    /// Encode to field element
    #[cfg(feature = "hashing")]
    pub fn encode<X>(msg: &[u8], dst: &[u8]) -> Self
    where
        X: hash2field::ExpandMsg<48>,
    {
        let random_bytes = X::expand_message(msg, dst);
        Self::from_okm(&random_bytes)
    }

    #[cfg(feature = "hashing")]
    /// Returns `self^by`, where `by` is a little-endian integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent.** If the exponent
    /// is fixed, this operation is effectively constant time.
    pub fn pow_vartime(&self, by: &[u32; 8]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            for i in (0..32).rev() {
                res = res.square();

                res.conditional_assign(&(res * self), Choice::from(((*e >> i) & 1) as u8));
            }
        }
        res
    }

    /// Optimized Simplified Shallue-van de Woestijne-Ulas map
    #[cfg(feature = "hashing")]
    pub fn osswu(&self) -> (Self, Self) {
        // See section 8.7 in
        // <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>
        const C1: [u32; 8] = [
            0xbfff_ff0b,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0x3fff_ffff,
        ];
        // 0x25e9711ae8c0dadc 0x46fdbcb72aadd8f4 0x250b65073012ec80 0xbc6ecb9c12973975
        const C2: FieldElement = FieldElement::from_bytes_unchecked(&[
            0x25, 0xe9, 0x71, 0x1a, 0xe8, 0xc0, 0xda, 0xdc, 0x46, 0xfd, 0xbc, 0xb7, 0x2a, 0xad,
            0xd8, 0xf4, 0x25, 0x0b, 0x65, 0x07, 0x30, 0x12, 0xec, 0x80, 0xbc, 0x6e, 0xcb, 0x9c,
            0x12, 0x97, 0x39, 0x75,
        ]);
        // 0x3f8731abdd661adc 0xa08a5558f0f5d272 0xe953d363cb6f0e5d 0x405447c01a444533
        const MAP_A: FieldElement = FieldElement::from_bytes_unchecked(&[
            0x3f, 0x87, 0x31, 0xab, 0xdd, 0x66, 0x1a, 0xdc, 0xa0, 0x8a, 0x55, 0x58, 0xf0, 0xf5,
            0xd2, 0x72, 0xe9, 0x53, 0xd3, 0x63, 0xcb, 0x6f, 0x0e, 0x5d, 0x40, 0x54, 0x47, 0xc0,
            0x1a, 0x44, 0x45, 0x33,
        ]);
        // 0x00000000000006eb
        const MAP_B: FieldElement = FieldElement::from_bytes_unchecked(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x06, 0xeb,
        ]);
        // 0xffffffffffffffff 0xffffffffffffffff 0xffffffffffffffff 0xfffffffefffffc24
        const Z: FieldElement = FieldElement::from_bytes_unchecked(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xff, 0xff, 0xfc, 0x24,
        ]);

        let tv1 = self.square(); // u^2
        let tv3 = Z * &tv1; // Z * u^2
        let mut tv2 = tv3.square(); // tv3^2
        let mut xd = tv2 + &tv3; // tv3^2 + tv3
        let x1n = MAP_B * &(xd + &Self::one()); // B * (xd + 1)
        xd = (xd * &MAP_A.negate(1)).normalize(); // -A * xd

        let tv = (&Z * &MAP_A).normalize();
        xd.conditional_assign(&tv, xd.is_zero());

        tv2 = xd.square(); //xd^2
        let gxd = tv2 * &xd; // xd^3
        tv2 = tv2 * &MAP_A; // A * tv2

        let mut gx1 = x1n * &(tv2 + &x1n.square()); //x1n *(tv2 + x1n^2)
        tv2 = gxd * &MAP_B; // B * gxd
        gx1 += tv2; // gx1 + tv2

        let mut tv4 = gxd.square(); // gxd^2
        tv2 = gx1 * &gxd; // gx1 * gxd
        tv4 *= tv2;

        let y1 = tv4.pow_vartime(&C1) * &tv2; // tv4^C1 * tv2
        let x2n = tv3 * &x1n; // tv3 * x1n

        let y2 = y1 * &C2 * &tv1 * self; // y1 * c2 * tv1 * u

        tv2 = y1.square() * &gxd; //y1^2 * gxd

        let e2 = tv2.normalize().ct_eq(&gx1.normalize());

        // if e2 , x = x1, else x = x2
        let mut x = Self::conditional_select(&x2n, &x1n, e2);
        // xn / xd
        x *= xd.invert().unwrap();

        // if e2, y = y1, else y = y2
        let mut y = Self::conditional_select(&y2, &y1, e2);

        y.conditional_assign(&y.negate(1), Choice::from(self.sgn0() ^ y.sgn0()));
        (x, y)
    }

    /// Map from the isogeny points to the secp256k1 main curve
    #[cfg(feature = "hashing")]
    pub fn isogeny(x: &Self, y: &Self) -> (Self, Self) {
        // See section E.1 in
        // <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>
        const XNUM: [FieldElement; 4] = [
            FieldElement::from_bytes_unchecked(&[
                0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38,
                0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8d,
                0xaa, 0xaa, 0xa8, 0xc7,
            ]),
            FieldElement::from_bytes_unchecked(&[
                0x07, 0xd3, 0xd4, 0xc8, 0x0b, 0xc3, 0x21, 0xd5, 0xb9, 0xf3, 0x15, 0xce, 0xa7, 0xfd,
                0x44, 0xc5, 0xd5, 0x95, 0xd2, 0xfc, 0x0b, 0xf6, 0x3b, 0x92, 0xdf, 0xff, 0x10, 0x44,
                0xf1, 0x7c, 0x65, 0x81,
            ]),
            FieldElement::from_bytes_unchecked(&[
                0x53, 0x4c, 0x32, 0x8d, 0x23, 0xf2, 0x34, 0xe6, 0xe2, 0xa4, 0x13, 0xde, 0xca, 0x25,
                0xca, 0xec, 0xe4, 0x50, 0x61, 0x44, 0x03, 0x7c, 0x40, 0x31, 0x4e, 0xcb, 0xd0, 0xb5,
                0x3d, 0x9d, 0xd2, 0x62,
            ]),
            FieldElement::from_bytes_unchecked(&[
                0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38,
                0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8d,
                0xaa, 0xaa, 0xa8, 0x8c,
            ]),
        ];
        const XDEN: [FieldElement; 3] = [
            FieldElement::from_bytes_unchecked(&[
                0xd3, 0x57, 0x71, 0x19, 0x3d, 0x94, 0x91, 0x8a, 0x9c, 0xa3, 0x4c, 0xcb, 0xb7, 0xb6,
                0x40, 0xdd, 0x86, 0xcd, 0x40, 0x95, 0x42, 0xf8, 0x48, 0x7d, 0x9f, 0xe6, 0xb7, 0x45,
                0x78, 0x1e, 0xb4, 0x9b,
            ]),
            FieldElement::from_bytes_unchecked(&[
                0xed, 0xad, 0xc6, 0xf6, 0x43, 0x83, 0xdc, 0x1d, 0xf7, 0xc4, 0xb2, 0xd5, 0x1b, 0x54,
                0x22, 0x54, 0x06, 0xd3, 0x6b, 0x64, 0x1f, 0x5e, 0x41, 0xbb, 0xc5, 0x2a, 0x56, 0x61,
                0x2a, 0x8c, 0x6d, 0x14,
            ]),
            FieldElement::from_bytes_unchecked(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ]),
        ];
        const YNUM: [FieldElement; 4] = [
            FieldElement::from_bytes_unchecked(&[
                0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84,
                0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b,
                0x8e, 0x38, 0xe2, 0x3c,
            ]),
            FieldElement::from_bytes_unchecked(&[
                0xc7, 0x5e, 0x0c, 0x32, 0xd5, 0xcb, 0x7c, 0x0f, 0xa9, 0xd0, 0xa5, 0x4b, 0x12, 0xa0,
                0xa6, 0xd5, 0x64, 0x7a, 0xb0, 0x46, 0xd6, 0x86, 0xda, 0x6f, 0xdf, 0xfc, 0x90, 0xfc,
                0x20, 0x1d, 0x71, 0xa3,
            ]),
            FieldElement::from_bytes_unchecked(&[
                0x29, 0xa6, 0x19, 0x46, 0x91, 0xf9, 0x1a, 0x73, 0x71, 0x52, 0x09, 0xef, 0x65, 0x12,
                0xe5, 0x76, 0x72, 0x28, 0x30, 0xa2, 0x01, 0xbe, 0x20, 0x18, 0xa7, 0x65, 0xe8, 0x5a,
                0x9e, 0xce, 0xe9, 0x31,
            ]),
            FieldElement::from_bytes_unchecked(&[
                0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12,
                0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f,
                0x38, 0xe3, 0x8d, 0x84,
            ]),
        ];
        const YDEN: [FieldElement; 4] = [
            FieldElement::from_bytes_unchecked(&[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                0xff, 0xff, 0xf9, 0x3b,
            ]),
            FieldElement::from_bytes_unchecked(&[
                0x7a, 0x06, 0x53, 0x4b, 0xb8, 0xbd, 0xb4, 0x9f, 0xd5, 0xe9, 0xe6, 0x63, 0x27, 0x22,
                0xc2, 0x98, 0x94, 0x67, 0xc1, 0xbf, 0xc8, 0xe8, 0xd9, 0x78, 0xdf, 0xb4, 0x25, 0xd2,
                0x68, 0x5c, 0x25, 0x73,
            ]),
            FieldElement::from_bytes_unchecked(&[
                0x64, 0x84, 0xaa, 0x71, 0x65, 0x45, 0xca, 0x2c, 0xf3, 0xa7, 0x0c, 0x3f, 0xa8, 0xfe,
                0x33, 0x7e, 0x0a, 0x3d, 0x21, 0x16, 0x2f, 0x0d, 0x62, 0x99, 0xa7, 0xbf, 0x81, 0x92,
                0xbf, 0xd2, 0xa7, 0x6f,
            ]),
            FieldElement::from_bytes_unchecked(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ]),
        ];
        const DEGREE: usize = 4;

        let mut xs = [Self::one(); DEGREE];
        xs[1] = *x;
        xs[2] = x.square();
        for i in 3..DEGREE {
            xs[i] = xs[i - 1] * x;
        }
        let x_num = Self::compute_iso(&xs, &XNUM);
        let x_den = Self::compute_iso(&xs, &XDEN).invert().unwrap();
        let y_num = Self::compute_iso(&xs, &YNUM) * y;
        let y_den = Self::compute_iso(&xs, &YDEN).invert().unwrap();

        (x_num * &x_den, y_num * &y_den)
    }

    /// Compute the ISO transform
    #[cfg(feature = "hashing")]
    fn compute_iso(xxs: &[Self], k: &[Self]) -> Self {
        let mut xx = Self::zero();
        for (xi, ki) in xxs.iter().zip(k.iter()) {
            xx += xi * ki;
        }
        xx
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(FieldElementImpl::conditional_select(&(a.0), &(b.0), choice))
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&(other.0))
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        Self::zero()
    }
}

impl DefaultIsZeroes for FieldElement {}

impl Eq for FieldElement {}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&(other.0)).into()
    }
}

impl Add<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: FieldElement) -> FieldElement {
        FieldElement(self.0.add(&(other.0)))
    }
}

impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0.add(&(other.0)))
    }
}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0.add(&(other.0)))
    }
}

impl AddAssign<FieldElement> for FieldElement {
    fn add_assign(&mut self, other: FieldElement) {
        *self = *self + &other;
    }
}

impl AddAssign<&FieldElement> for FieldElement {
    fn add_assign(&mut self, other: &FieldElement) {
        *self = *self + other;
    }
}

impl Sub<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: FieldElement) -> FieldElement {
        self + -other
    }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        self + -other
    }
}

impl SubAssign<FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: FieldElement) {
        *self = *self + -other;
    }
}

impl SubAssign<&FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: &FieldElement) {
        *self = *self + -other;
    }
}

impl Mul<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: FieldElement) -> FieldElement {
        FieldElement(self.0.mul(&(other.0)))
    }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0.mul(&(other.0)))
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement(self.0.mul(&(other.0)))
    }
}

impl MulAssign<FieldElement> for FieldElement {
    fn mul_assign(&mut self, rhs: FieldElement) {
        *self = *self * &rhs;
    }
}

impl MulAssign<&FieldElement> for FieldElement {
    fn mul_assign(&mut self, rhs: &FieldElement) {
        *self = *self * rhs;
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        self.negate(1)
    }
}

impl Neg for &FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        self.negate(1)
    }
}

#[cfg(feature = "hashing")]
impl FromOkm<48> for FieldElement {
    fn from_okm(bytes: &[u8; 48]) -> Self {
        // 0x0000000000000001000000000000000000000000000000000000000000000000
        const F_2_192: FieldElement = FieldElement::from_bytes_unchecked(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        let d0 = FieldElement::from_bytes_unchecked(&[
            0, 0, 0, 0, 0, 0, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
            bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21],
            bytes[22], bytes[23],
        ]);
        let d1 = FieldElement::from_bytes_unchecked(&[
            0, 0, 0, 0, 0, 0, 0, 0, bytes[24], bytes[25], bytes[26], bytes[27], bytes[28],
            bytes[29], bytes[30], bytes[31], bytes[32], bytes[33], bytes[34], bytes[35], bytes[36],
            bytes[37], bytes[38], bytes[39], bytes[40], bytes[41], bytes[42], bytes[43], bytes[44],
            bytes[45], bytes[46], bytes[47],
        ]);
        d0 * &F_2_192 + &d1
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::ff::Field;
    use num_bigint::{BigUint, ToBigUint};
    use proptest::prelude::*;

    use super::FieldElement;
    use crate::{
        arithmetic::dev::{biguint_to_bytes, bytes_to_biguint},
        test_vectors::field::DBL_TEST_VECTORS,
        FieldBytes,
    };

    impl From<&BigUint> for FieldElement {
        fn from(x: &BigUint) -> Self {
            let bytes = biguint_to_bytes(x);
            Self::from_bytes(&bytes.into()).unwrap()
        }
    }

    impl ToBigUint for FieldElement {
        fn to_biguint(&self) -> Option<BigUint> {
            Some(bytes_to_biguint(self.to_bytes().as_ref()))
        }
    }

    #[test]
    fn zero_is_additive_identity() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();
        assert_eq!((zero + &zero).normalize(), zero);
        assert_eq!((one + &zero).normalize(), one);
    }

    #[test]
    fn one_is_multiplicative_identity() {
        let one = FieldElement::one();
        assert_eq!((one * &one).normalize(), one);
    }

    #[test]
    fn from_bytes() {
        assert_eq!(
            FieldElement::from_bytes(&FieldBytes::default()).unwrap(),
            FieldElement::zero()
        );
        assert_eq!(
            FieldElement::from_bytes(
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 1
                ]
                .into()
            )
            .unwrap(),
            FieldElement::one()
        );
        assert!(bool::from(
            FieldElement::from_bytes(&[0xff; 32].into()).is_none()
        ));
    }

    #[test]
    fn to_bytes() {
        assert_eq!(FieldElement::zero().to_bytes(), [0; 32].into());
        assert_eq!(
            FieldElement::one().to_bytes(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ]
            .into()
        );
    }

    #[test]
    fn repeated_add() {
        let mut r = FieldElement::one();
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(r.to_bytes(), DBL_TEST_VECTORS[i].into());
            r = (r + &r).normalize();
        }
    }

    #[test]
    fn repeated_double() {
        let mut r = FieldElement::one();
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(r.to_bytes(), DBL_TEST_VECTORS[i].into());
            r = r.double().normalize();
        }
    }

    #[test]
    fn repeated_mul() {
        let mut r = FieldElement::one();
        let two = r + &r;
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(r.normalize().to_bytes(), DBL_TEST_VECTORS[i].into());
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

    prop_compose! {
        fn field_element()(bytes in any::<[u8; 32]>()) -> FieldElement {
            let mut res = bytes_to_biguint(&bytes);
            let m = FieldElement::modulus_as_biguint();
            // Modulus is 256 bit long, same as the maximum `res`,
            // so this is guaranteed to land us in the correct range.
            if res >= m {
                res -= m;
            }
            FieldElement::from(&res)
        }
    }

    proptest! {

        #[test]
        fn fuzzy_add(
            a in field_element(),
            b in field_element()
        ) {
            let a_bi = a.to_biguint().unwrap();
            let b_bi = b.to_biguint().unwrap();
            let res_bi = (&a_bi + &b_bi) % FieldElement::modulus_as_biguint();
            let res_ref = FieldElement::from(&res_bi);
            let res_test = (&a + &b).normalize();
            assert_eq!(res_test, res_ref);
        }

        #[test]
        fn fuzzy_mul(
            a in field_element(),
            b in field_element()
        ) {
            let a_bi = a.to_biguint().unwrap();
            let b_bi = b.to_biguint().unwrap();
            let res_bi = (&a_bi * &b_bi) % FieldElement::modulus_as_biguint();
            let res_ref = FieldElement::from(&res_bi);
            let res_test = (&a * &b).normalize();
            assert_eq!(res_test, res_ref);
        }

        #[test]
        fn fuzzy_square(
            a in field_element()
        ) {
            let a_bi = a.to_biguint().unwrap();
            let res_bi = (&a_bi * &a_bi) % FieldElement::modulus_as_biguint();
            let res_ref = FieldElement::from(&res_bi);
            let res_test = a.square().normalize();
            assert_eq!(res_test, res_ref);
        }

        #[test]
        fn fuzzy_negate(
            a in field_element()
        ) {
            let m = FieldElement::modulus_as_biguint();
            let a_bi = a.to_biguint().unwrap();
            let res_bi = (&m - &a_bi) % &m;
            let res_ref = FieldElement::from(&res_bi);
            let res_test = a.negate(1).normalize();
            assert_eq!(res_test, res_ref);
        }

        #[test]
        fn fuzzy_sqrt(
            a in field_element()
        ) {
            let m = FieldElement::modulus_as_biguint();
            let a_bi = a.to_biguint().unwrap();
            let sqr_bi = (&a_bi * &a_bi) % &m;
            let sqr = FieldElement::from(&sqr_bi);

            let res_ref1 = a;
            let possible_sqrt = (&m - &a_bi) % &m;
            let res_ref2 = FieldElement::from(&possible_sqrt);
            let res_test = sqr.sqrt().unwrap().normalize();
            // FIXME: is there a rule which square root is returned?
            assert!(res_test == res_ref1 || res_test == res_ref2);
        }

        #[test]
        fn fuzzy_invert(
            a in field_element()
        ) {
            let a = if bool::from(a.is_zero()) { FieldElement::one() } else { a };
            let a_bi = a.to_biguint().unwrap();
            let inv = a.invert().unwrap().normalize();
            let inv_bi = inv.to_biguint().unwrap();
            let m = FieldElement::modulus_as_biguint();
            assert_eq!((&inv_bi * &a_bi) % &m, 1.to_biguint().unwrap());
        }
    }
}
