//! Field arithmetic modulo p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1

#![allow(clippy::assign_op_pattern, clippy::op_ref)]

use crate::{
    arithmetic::util::{adc, mac, sbb},
    FieldBytes,
};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    ff::Field,
    rand_core::RngCore,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
};
#[cfg(feature = "hashing")]
use hash2field::FromOkm;

/// The number of 64-bit limbs used to represent a [`FieldElement`].
const LIMBS: usize = 4;

/// Constant representing the modulus
/// p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1
pub const MODULUS: FieldElement = FieldElement([
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
]);

/// R = 2^256 mod p
const R: FieldElement = FieldElement([
    0x0000_0000_0000_0001,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_fffe,
]);

/// R^2 = 2^512 mod p
const R2: FieldElement = FieldElement([
    0x0000_0000_0000_0003,
    0xffff_fffb_ffff_ffff,
    0xffff_ffff_ffff_fffe,
    0x0000_0004_ffff_fffd,
]);

/// An element in the finite field modulo p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1.
///
/// The internal representation is in little-endian order. Elements are always in
/// Montgomery form; i.e., FieldElement(a) = aR mod p, with R = 2^256.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(crate) [u64; LIMBS]);

impl Field for FieldElement {
    fn random(mut rng: impl RngCore) -> Self {
        // We reduce a random 512-bit value into a 256-bit field, which results in a
        // negligible bias from the uniform distribution.
        let mut buf = [0; 64];
        rng.fill_bytes(&mut buf);
        FieldElement::from_bytes_wide(buf)
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

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &FieldElement, b: &FieldElement, choice: Choice) -> FieldElement {
        FieldElement([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        FieldElement::zero()
    }
}

impl DefaultIsZeroes for FieldElement {}

impl Eq for FieldElement {}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl FieldElement {
    /// Zero element.
    pub const ZERO: Self = FieldElement([0, 0, 0, 0]);

    /// Multiplicative identity.
    pub const ONE: Self = R;

    fn from_bytes_wide(bytes: [u8; 64]) -> Self {
        FieldElement::montgomery_reduce(
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
            u64::from_be_bytes(bytes[40..48].try_into().unwrap()),
            u64::from_be_bytes(bytes[48..56].try_into().unwrap()),
            u64::from_be_bytes(bytes[56..64].try_into().unwrap()),
        )
    }

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: &FieldBytes) -> CtOption<Self> {
        let mut w = [0u64; LIMBS];

        // Interpret the bytes as a big-endian integer w.
        w[3] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        w[2] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        w[1] = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        w[0] = u64::from_be_bytes(bytes[24..32].try_into().unwrap());

        // If w is in the range [0, p) then w - p will overflow, resulting in a borrow
        // value of 2^64 - 1.
        let (_, borrow) = sbb(w[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb(w[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb(w[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb(w[3], MODULUS.0[3], borrow);
        let is_some = (borrow as u8) & 1;

        // Convert w to Montgomery form: w * R^2 * R^-1 mod p = wR mod p
        CtOption::new(FieldElement(w).to_montgomery(), Choice::from(is_some))
    }

    /// Returns the SEC1 encoding of this field element.
    pub fn to_bytes(self) -> FieldBytes {
        // Convert from Montgomery form to canonical form
        let tmp = self.to_canonical();

        let mut ret = FieldBytes::default();
        ret[0..8].copy_from_slice(&tmp.0[3].to_be_bytes());
        ret[8..16].copy_from_slice(&tmp.0[2].to_be_bytes());
        ret[16..24].copy_from_slice(&tmp.0[1].to_be_bytes());
        ret[24..32].copy_from_slice(&tmp.0[0].to_be_bytes());
        ret
    }

    /// Determine if this `FieldElement` is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&FieldElement::zero())
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
        // Bit 256 of p is set, so addition can result in five words.
        let (w0, carry) = adc(self.0[0], rhs.0[0], 0);
        let (w1, carry) = adc(self.0[1], rhs.0[1], carry);
        let (w2, carry) = adc(self.0[2], rhs.0[2], carry);
        let (w3, w4) = adc(self.0[3], rhs.0[3], carry);

        // Attempt to subtract the modulus, to ensure the result is in the field.
        let (result, _) = Self::sub_inner(
            w0,
            w1,
            w2,
            w3,
            w4,
            MODULUS.0[0],
            MODULUS.0[1],
            MODULUS.0[2],
            MODULUS.0[3],
            0,
        );
        result
    }

    /// Returns 2*self.
    pub const fn double(&self) -> Self {
        self.add(self)
    }

    /// Returns self - rhs mod p
    pub const fn subtract(&self, rhs: &Self) -> Self {
        let (result, _) = Self::sub_inner(
            self.0[0], self.0[1], self.0[2], self.0[3], 0, rhs.0[0], rhs.0[1], rhs.0[2], rhs.0[3],
            0,
        );
        result
    }

    /// Returns self - rhs mod p
    pub(crate) const fn informed_subtract(&self, rhs: &Self) -> (Self, u64) {
        Self::sub_inner(
            self.0[0], self.0[1], self.0[2], self.0[3], 0, rhs.0[0], rhs.0[1], rhs.0[2], rhs.0[3],
            0,
        )
    }
    #[inline]
    #[allow(clippy::too_many_arguments)]
    const fn sub_inner(
        l0: u64,
        l1: u64,
        l2: u64,
        l3: u64,
        l4: u64,
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
    ) -> (Self, u64) {
        let (w0, borrow) = sbb(l0, r0, 0);
        let (w1, borrow) = sbb(l1, r1, borrow);
        let (w2, borrow) = sbb(l2, r2, borrow);
        let (w3, borrow) = sbb(l3, r3, borrow);
        let (_, borrow) = sbb(l4, r4, borrow);

        // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the
        // modulus.
        let (w0, carry) = adc(w0, MODULUS.0[0] & borrow, 0);
        let (w1, carry) = adc(w1, MODULUS.0[1] & borrow, carry);
        let (w2, carry) = adc(w2, MODULUS.0[2] & borrow, carry);
        let (w3, _) = adc(w3, MODULUS.0[3] & borrow, carry);

        (FieldElement([w0, w1, w2, w3]), borrow)
    }

    /// Montgomery Reduction
    ///
    /// The general algorithm is:
    /// ```text
    /// A <- input (2n b-limbs)
    /// for i in 0..n {
    ///     k <- A[i] p' mod b
    ///     A <- A + k p b^i
    /// }
    /// A <- A / b^n
    /// if A >= p {
    ///     A <- A - p
    /// }
    /// ```
    ///
    /// For secp256r1, we have the following simplifications:
    ///
    /// - `p'` is 1, so our multiplicand is simply the first limb of the intermediate A.
    ///
    /// - The first limb of p is 2^64 - 1; multiplications by this limb can be simplified
    ///   to a shift and subtraction:
    ///   ```text
    ///       a_i * (2^64 - 1) = a_i * 2^64 - a_i = (a_i << 64) - a_i
    ///   ```
    ///   However, because `p' = 1`, the first limb of p is multiplied by limb i of the
    ///   intermediate A and then immediately added to that same limb, so we simply
    ///   initialize the carry to limb i of the intermediate.
    ///
    /// - The third limb of p is zero, so we can ignore any multiplications by it and just
    ///   add the carry.
    ///
    /// References:
    /// - Handbook of Applied Cryptography, Chapter 14
    ///   Algorithm 14.32
    ///   http://cacr.uwaterloo.ca/hac/about/chap14.pdf
    ///
    /// - Efficient and Secure Elliptic Curve Cryptography Implementation of Curve P-256
    ///   Algorithm 7) Montgomery Word-by-Word Reduction
    ///   https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session6-adalier-mehmet.pdf
    #[inline]
    #[allow(clippy::too_many_arguments)]
    const fn montgomery_reduce(
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
        r6: u64,
        r7: u64,
    ) -> Self {
        let (r1, carry) = mac(r1, r0, MODULUS.0[1], r0);
        let (r2, carry) = adc(r2, 0, carry);
        let (r3, carry) = mac(r3, r0, MODULUS.0[3], carry);
        let (r4, carry2) = adc(r4, 0, carry);

        let (r2, carry) = mac(r2, r1, MODULUS.0[1], r1);
        let (r3, carry) = adc(r3, 0, carry);
        let (r4, carry) = mac(r4, r1, MODULUS.0[3], carry);
        let (r5, carry2) = adc(r5, carry2, carry);

        let (r3, carry) = mac(r3, r2, MODULUS.0[1], r2);
        let (r4, carry) = adc(r4, 0, carry);
        let (r5, carry) = mac(r5, r2, MODULUS.0[3], carry);
        let (r6, carry2) = adc(r6, carry2, carry);

        let (r4, carry) = mac(r4, r3, MODULUS.0[1], r3);
        let (r5, carry) = adc(r5, 0, carry);
        let (r6, carry) = mac(r6, r3, MODULUS.0[3], carry);
        let (r7, r8) = adc(r7, carry2, carry);

        // Result may be within MODULUS of the correct value
        let (result, _) = Self::sub_inner(
            r4,
            r5,
            r6,
            r7,
            r8,
            MODULUS.0[0],
            MODULUS.0[1],
            MODULUS.0[2],
            MODULUS.0[3],
            0,
        );
        result
    }

    /// Translate a field element out of the Montgomery domain.
    #[inline]
    pub(crate) const fn to_canonical(self) -> Self {
        FieldElement::montgomery_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0)
    }

    /// Translate a field element into the Montgomery domain.
    #[inline]
    pub(crate) const fn to_montgomery(self) -> Self {
        Self::mul(&self, &R2)
    }

    /// Returns self * rhs mod p
    pub const fn mul(&self, rhs: &Self) -> Self {
        // Schoolbook multiplication.

        let (w0, carry) = mac(0, self.0[0], rhs.0[0], 0);
        let (w1, carry) = mac(0, self.0[0], rhs.0[1], carry);
        let (w2, carry) = mac(0, self.0[0], rhs.0[2], carry);
        let (w3, w4) = mac(0, self.0[0], rhs.0[3], carry);

        let (w1, carry) = mac(w1, self.0[1], rhs.0[0], 0);
        let (w2, carry) = mac(w2, self.0[1], rhs.0[1], carry);
        let (w3, carry) = mac(w3, self.0[1], rhs.0[2], carry);
        let (w4, w5) = mac(w4, self.0[1], rhs.0[3], carry);

        let (w2, carry) = mac(w2, self.0[2], rhs.0[0], 0);
        let (w3, carry) = mac(w3, self.0[2], rhs.0[1], carry);
        let (w4, carry) = mac(w4, self.0[2], rhs.0[2], carry);
        let (w5, w6) = mac(w5, self.0[2], rhs.0[3], carry);

        let (w3, carry) = mac(w3, self.0[3], rhs.0[0], 0);
        let (w4, carry) = mac(w4, self.0[3], rhs.0[1], carry);
        let (w5, carry) = mac(w5, self.0[3], rhs.0[2], carry);
        let (w6, w7) = mac(w6, self.0[3], rhs.0[3], carry);

        FieldElement::montgomery_reduce(w0, w1, w2, w3, w4, w5, w6, w7)
    }

    /// Returns self * self mod p
    pub const fn square(&self) -> Self {
        // Schoolbook multiplication.
        self.mul(self)
    }

    /// Returns `self^by`, where `by` is a little-endian integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent.** If the exponent
    /// is fixed, this operation is effectively constant time.
    pub fn pow_vartime(&self, by: &[u64; 4]) -> Self {
        let mut res = Self::one();
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
        // We need to find b such that b * a ≡ 1 mod p. As we are in a prime
        // field, we can apply Fermat's Little Theorem:
        //
        //    a^p         ≡ a mod p
        //    a^(p-1)     ≡ 1 mod p
        //    a^(p-2) * a ≡ 1 mod p
        //
        // Thus inversion can be implemented with a single exponentiation.
        let inverse = self.pow_vartime(&[
            0xffff_ffff_ffff_fffd,
            0x0000_0000_ffff_ffff,
            0x0000_0000_0000_0000,
            0xffff_ffff_0000_0001,
        ]);

        CtOption::new(inverse, !self.is_zero())
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

        let sqrt = self.pow_vartime(&[
            0x0000_0000_0000_0000,
            0x0000_0000_4000_0000,
            0x4000_0000_0000_0000,
            0x3fff_ffff_c000_0000,
        ]);

        CtOption::new(
            sqrt,
            (&sqrt * &sqrt).ct_eq(self), // Only return Some if it's the square root.
        )
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

    /// Optimized Simplified Shallue-van de Woestijne-Ulas
    #[cfg(feature = "hashing")]
    pub fn osswu(&self) -> (FieldElement, FieldElement) {
        // See section 8.2 in
        // <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>
        const C1: [u64; 4] = [
            0xffff_ffff_ffff_ffff,
            0x0000_0000_3fff_ffff,
            0x4000_0000_0000_0000,
            0x3fff_ffff_c000_0000,
        ];
        const C2: FieldElement = FieldElement([
            0x53e4_3951_f64f_dbe7,
            0xb280_6c63_966a_1a66,
            0x1ac5_d59c_3298_bf50,
            0xa332_3851_ba99_7e27,
        ]);
        const MAP_A: FieldElement = FieldElement([
            0xffff_ffff_ffff_fffc,
            0x0000_0003_ffff_ffff,
            0x0000_0000_0000_0000,
            0xffff_fffc_0000_0004,
        ]);
        const MAP_B: FieldElement = FieldElement([
            0xd89c_df62_29c4_bddf,
            0xacf0_05cd_7884_3090,
            0xe5a2_20ab_f721_2ed6,
            0xdc30_061d_0487_4834,
        ]);
        const Z: FieldElement = FieldElement([
            0xffff_ffff_ffff_fff5,
            0x0000_000a_ffff_ffff,
            0x0000_0000_0000_0000,
            0xffff_fff5_0000_000b,
        ]);

        let tv1 = self.square(); // u^2
        let tv3 = Z * &tv1; // Z * u^2
        let mut tv2 = tv3.square(); // tv3^2
        let mut xd = tv2 + &tv3; // tv3^2 + tv3
        let x1n = MAP_B * &(xd + &Self::one()); // B * (xd + 1)
        let a_neg = -MAP_A;
        xd *= a_neg; // -A * xd

        let tv = &Z * &MAP_A;
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

        let e2 = tv2.ct_eq(&gx1);

        // if e2 , x = x1, else x = x2
        let mut x = Self::conditional_select(&x2n, &x1n, e2);
        // xn / xd
        x *= xd.invert().unwrap();

        // if e2, y = y1, else y = y2
        let mut y = Self::conditional_select(&y2, &y1, e2);

        y.conditional_assign(&-y, Choice::from(self.sgn0() ^ y.sgn0()));
        (x, y)
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
        FieldElement::subtract(&self, &other)
    }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        FieldElement::subtract(&self, other)
    }
}

impl Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn sub(self, other: &FieldElement) -> FieldElement {
        FieldElement::subtract(self, other)
    }
}

impl SubAssign<FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: FieldElement) {
        *self = FieldElement::subtract(self, &other);
    }
}

impl SubAssign<&FieldElement> for FieldElement {
    fn sub_assign(&mut self, other: &FieldElement) {
        *self = FieldElement::subtract(self, other);
    }
}

impl Mul<FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: FieldElement) -> FieldElement {
        FieldElement::mul(&self, &other)
    }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement::mul(&self, other)
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        FieldElement::mul(self, other)
    }
}

impl MulAssign<FieldElement> for FieldElement {
    fn mul_assign(&mut self, other: FieldElement) {
        *self = FieldElement::mul(self, &other);
    }
}

impl MulAssign<&FieldElement> for FieldElement {
    fn mul_assign(&mut self, other: &FieldElement) {
        *self = FieldElement::mul(self, other);
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement::zero() - &self
    }
}

impl Neg for &FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement::zero() - self
    }
}

#[cfg(feature = "hashing")]
impl FromOkm<48> for FieldElement {
    fn from_okm(bytes: &[u8; 48]) -> Self {
        const F_2_192: FieldElement = FieldElement([
            0xffff_fffe_ffff_ffffu64,
            0xffff_ffff_ffff_fffeu64,
            0x0000_0002_0000_0000u64,
            0x0000_0000_0000_0003u64,
        ]);
        let d0 = FieldElement([
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            0,
        ])
        .to_montgomery();
        let d1 = FieldElement([
            u64::from_be_bytes(bytes[40..48].try_into().unwrap()),
            u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            0,
        ])
        .to_montgomery();
        d0 * &F_2_192 + &d1
    }
}

#[cfg(test)]
mod tests {
    use super::FieldElement;
    use crate::{test_vectors::field::DBL_TEST_VECTORS, FieldBytes};
    use elliptic_curve::ff::Field;
    use proptest::{num::u64::ANY, prelude::*};

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
        assert_eq!(FieldElement::zero().to_bytes(), FieldBytes::default());
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
            r = r + &r;
        }
    }

    #[test]
    fn repeated_double() {
        let mut r = FieldElement::one();
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(r.to_bytes(), DBL_TEST_VECTORS[i].into());
            r = r.double();
        }
    }

    #[test]
    fn repeated_mul() {
        let mut r = FieldElement::one();
        let two = r + &r;
        for i in 0..DBL_TEST_VECTORS.len() {
            assert_eq!(r.to_bytes(), DBL_TEST_VECTORS[i].into());
            r = r * &two;
        }
    }

    #[test]
    fn negation() {
        let two = FieldElement::one().double();
        let neg_two = -two;
        assert_eq!(two + &neg_two, FieldElement::zero());
        assert_eq!(-neg_two, two);
    }

    #[test]
    fn pow_vartime() {
        let one = FieldElement::one();
        let two = one + &one;
        let four = two.square();
        assert_eq!(two.pow_vartime(&[2, 0, 0, 0]), four);
    }

    #[test]
    fn invert() {
        assert!(bool::from(FieldElement::zero().invert().is_none()));

        let one = FieldElement::one();
        assert_eq!(one.invert().unwrap(), one);

        let two = one + &one;
        let inv_two = two.invert().unwrap();
        assert_eq!(two * &inv_two, one);
    }

    #[test]
    fn sqrt() {
        let one = FieldElement::one();
        let two = one + &one;
        let four = two.square();
        assert_eq!(four.sqrt().unwrap(), two);
    }

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
            let a = FieldElement([a0, a1, a2, 0]);
            let b = FieldElement([b0, b1, b2, 0]);
            assert_eq!(a.add(&b).subtract(&a), b);
        }
    }
}
