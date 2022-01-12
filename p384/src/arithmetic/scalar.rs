//! Scalar field elements for the NIST P-384 elliptic curve.

// TODO(tarcieri): 32-bit backend
#[cfg(not(target_pointer_width = "64"))]
compile_error!("scalar arithmetic is only supported on 64-bit platforms");

use crate::{FieldBytes, NistP384, ScalarCore, ORDER as MODULUS, U384};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    bigint::Limb,
    ff::{Field, PrimeField},
    generic_array::arr,
    ops::Reduce,
    rand_core::RngCore,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    Curve as _, Error, IsHigh, Result, ScalarArithmetic,
};

/// -(m^{-1} mod m) mod m
const INV: u64 = 7986114184663260229;

impl ScalarArithmetic for NistP384 {
    type Scalar = Scalar;
}

/// Scalars are elements in the finite field modulo n.
///
/// # ⚠️ WARNING: experimental implementation!
///
/// The scalar arithmetic implementation provided by this type is experimental,
/// poorly tested, and may produce incorrect results.
///
/// We do not recommend using it in any sort of production capacity at this time.
///
/// USE AT YOUR OWN RISK!
///
/// # Trait impls
///
/// Much of the important functionality of scalars is provided by traits from
/// the [`ff`](https://docs.rs/ff/) crate, which is re-exported as
/// `p384::elliptic_curve::ff`:
///
/// - [`Field`](https://docs.rs/ff/latest/ff/trait.Field.html) -
///   represents elements of finite fields and provides:
///   - [`Field::random`](https://docs.rs/ff/latest/ff/trait.Field.html#tymethod.random) -
///     generate a random scalar
///   - `double`, `square`, and `invert` operations
///   - Bounds for [`Add`], [`Sub`], [`Mul`], and [`Neg`] (as well as `*Assign` equivalents)
///   - Bounds for [`ConditionallySelectable`] from the `subtle` crate
/// - [`PrimeField`](https://docs.rs/ff/0.9.0/ff/trait.PrimeField.html) -
///   represents elements of prime fields and provides:
///   - `from_repr`/`to_repr` for converting field elements from/to big integers.
///   - `multiplicative_generator` and `root_of_unity` constants.
///
/// Please see the documentation for the relevant traits for more information.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(docsrs, doc(cfg(feature = "broken-arithmetic-do-not-use")))]
pub struct Scalar(ScalarCore);

impl Field for Scalar {
    fn random(mut rng: impl RngCore) -> Self {
        // NOTE: can't use ScalarCore::random due to CryptoRng bound
        let mut bytes = FieldBytes::default();

        loop {
            rng.fill_bytes(&mut bytes);
            if let Some(scalar) = Self::from_repr(bytes).into() {
                return scalar;
            }
        }
    }

    fn zero() -> Self {
        Self::ZERO
    }

    fn one() -> Self {
        Self::ONE
    }

    fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    #[must_use]
    fn square(&self) -> Self {
        self.square()
    }

    #[must_use]
    fn double(&self) -> Self {
        self.add(self)
    }

    fn invert(&self) -> CtOption<Self> {
        todo!()
    }

    fn sqrt(&self) -> CtOption<Self> {
        todo!()
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const NUM_BITS: u32 = 384;
    const CAPACITY: u32 = 383;
    const S: u32 = 1;

    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        ScalarCore::from_be_bytes(bytes).map(Self)
    }

    fn to_repr(&self) -> FieldBytes {
        self.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }

    fn multiplicative_generator() -> Self {
        2u64.into()
    }

    fn root_of_unity() -> Self {
        Scalar::from_repr(arr![u8;
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
            0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x72
        ])
        .unwrap()
    }
}

impl Scalar {
    /// Zero scalar.
    pub const ZERO: Self = Self(ScalarCore::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = Self(ScalarCore::ONE);

    /// Returns the SEC1 encoding of this scalar.
    pub fn to_bytes(&self) -> FieldBytes {
        self.0.to_be_bytes()
    }

    /// Multiply a scalar by another scalar.
    #[cfg(target_pointer_width = "64")]
    #[inline]
    pub fn mul(&self, other: &Scalar) -> Self {
        // TODO(tarcieri): replace with a.mul_wide(&b)
        let a = self.0.as_limbs();
        let b = other.0.as_limbs();

        let carry = Limb::ZERO;
        let (r0, carry) = Limb::ZERO.mac(a[0], b[0], carry);
        let (r1, carry) = Limb::ZERO.mac(a[0], b[1], carry);
        let (r2, carry) = Limb::ZERO.mac(a[0], b[2], carry);
        let (r3, carry) = Limb::ZERO.mac(a[0], b[3], carry);
        let (r4, carry) = Limb::ZERO.mac(a[0], b[4], carry);
        let (r5, carry) = Limb::ZERO.mac(a[0], b[5], carry);
        let r6 = carry;

        let carry = Limb::ZERO;
        let (r1, carry) = r1.mac(a[1], b[0], carry);
        let (r2, carry) = r2.mac(a[1], b[1], carry);
        let (r3, carry) = r3.mac(a[1], b[2], carry);
        let (r4, carry) = r4.mac(a[1], b[3], carry);
        let (r5, carry) = r5.mac(a[1], b[4], carry);
        let (r6, carry) = r6.mac(a[1], b[5], carry);
        let r7 = carry;

        let carry = Limb::ZERO;
        let (r2, carry) = r2.mac(a[2], b[0], carry);
        let (r3, carry) = r3.mac(a[2], b[1], carry);
        let (r4, carry) = r4.mac(a[2], b[2], carry);
        let (r5, carry) = r5.mac(a[2], b[3], carry);
        let (r6, carry) = r6.mac(a[2], b[4], carry);
        let (r7, carry) = r7.mac(a[2], b[5], carry);
        let r8 = carry;

        let carry = Limb::ZERO;
        let (r3, carry) = r3.mac(a[3], b[0], carry);
        let (r4, carry) = r4.mac(a[3], b[1], carry);
        let (r5, carry) = r5.mac(a[3], b[2], carry);
        let (r6, carry) = r6.mac(a[3], b[3], carry);
        let (r7, carry) = r7.mac(a[3], b[4], carry);
        let (r8, carry) = r8.mac(a[3], b[5], carry);
        let r9 = carry;

        let carry = Limb::ZERO;
        let (r4, carry) = r4.mac(a[4], b[0], carry);
        let (r5, carry) = r5.mac(a[4], b[1], carry);
        let (r6, carry) = r6.mac(a[4], b[2], carry);
        let (r7, carry) = r7.mac(a[4], b[3], carry);
        let (r8, carry) = r8.mac(a[4], b[4], carry);
        let (r9, carry) = r9.mac(a[4], b[5], carry);
        let r10 = carry;

        let carry = Limb::ZERO;
        let (r5, carry) = r5.mac(a[5], b[0], carry);
        let (r6, carry) = r6.mac(a[5], b[1], carry);
        let (r7, carry) = r7.mac(a[5], b[2], carry);
        let (r8, carry) = r8.mac(a[5], b[3], carry);
        let (r9, carry) = r9.mac(a[5], b[4], carry);
        let (r10, carry) = r10.mac(a[5], b[5], carry);
        let r11 = carry;

        Self::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11)
    }

    /// Compute modular square.
    #[must_use]
    pub fn square(&self) -> Self {
        // NOTE: generated by `ff_derive`
        let limbs = self.0.as_limbs();

        let carry = Limb::ZERO;
        let (r1, carry) = Limb::ZERO.mac(limbs[0], limbs[1], carry);
        let (r2, carry) = Limb::ZERO.mac(limbs[0], limbs[2], carry);
        let (r3, carry) = Limb::ZERO.mac(limbs[0], limbs[3], carry);
        let (r4, carry) = Limb::ZERO.mac(limbs[0], limbs[4], carry);
        let (r5, carry) = Limb::ZERO.mac(limbs[0], limbs[5], carry);
        let r6 = carry;

        let carry = Limb::ZERO;
        let (r3, carry) = r3.mac(limbs[1], limbs[2], carry);
        let (r4, carry) = r4.mac(limbs[1], limbs[3], carry);
        let (r5, carry) = r5.mac(limbs[1], limbs[4], carry);
        let (r6, carry) = r6.mac(limbs[1], limbs[5], carry);
        let r7 = carry;

        let carry = Limb::ZERO;
        let (r5, carry) = r5.mac(limbs[2], limbs[3], carry);
        let (r6, carry) = r6.mac(limbs[2], limbs[4], carry);
        let (r7, carry) = r7.mac(limbs[2], limbs[5], carry);
        let r8 = carry;

        let carry = Limb::ZERO;
        let (r7, carry) = r7.mac(limbs[3], limbs[4], carry);
        let (r8, carry) = r8.mac(limbs[3], limbs[5], carry);
        let r9 = carry;

        let carry = Limb::ZERO;
        let (r9, carry) = r9.mac(limbs[4], limbs[5], carry);
        let r10 = carry;
        let r11 = Limb(r10.0 >> 63);
        let r10 = Limb((r10.0 << 1) | (r9.0 >> 63));
        let r9 = Limb((r9.0 << 1) | (r8.0 >> 63));
        let r8 = Limb((r8.0 << 1) | (r7.0 >> 63));
        let r7 = Limb((r7.0 << 1) | (r6.0 >> 63));
        let r6 = Limb((r6.0 << 1) | (r5.0 >> 63));
        let r5 = Limb((r5.0 << 1) | (r4.0 >> 63));
        let r4 = Limb((r4.0 << 1) | (r3.0 >> 63));
        let r3 = Limb((r3.0 << 1) | (r2.0 >> 63));
        let r2 = Limb((r2.0 << 1) | (r1.0 >> 63));
        let r1 = Limb(r1.0 << 1);

        let carry = Limb::ZERO;
        let (r0, carry) = Limb::ZERO.mac(limbs[0], limbs[0], carry);
        let (r1, carry) = r1.adc(Limb::ZERO, carry);
        let (r2, carry) = r2.mac(limbs[1], limbs[1], carry);
        let (r3, carry) = r3.adc(Limb::ZERO, carry);
        let (r4, carry) = r4.mac(limbs[2], limbs[2], carry);
        let (r5, carry) = r5.adc(Limb::ZERO, carry);
        let (r6, carry) = r6.mac(limbs[3], limbs[3], carry);
        let (r7, carry) = r7.adc(Limb::ZERO, carry);
        let (r8, carry) = r8.mac(limbs[4], limbs[4], carry);
        let (r9, carry) = r9.adc(Limb::ZERO, carry);
        let (r10, carry) = r10.mac(limbs[5], limbs[5], carry);
        let (r11, _) = r11.adc(Limb::ZERO, carry);

        Self::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11)
    }

    /// Montgomery reduction.
    #[cfg(target_pointer_width = "64")]
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn montgomery_reduce(
        r0: Limb,
        r1: Limb,
        r2: Limb,
        r3: Limb,
        r4: Limb,
        r5: Limb,
        r6: Limb,
        r7: Limb,
        r8: Limb,
        r9: Limb,
        r10: Limb,
        r11: Limb,
    ) -> Self {
        // NOTE: generated by `ff_derive`
        let modulus = MODULUS.limbs();

        let k = r0.wrapping_mul(Limb(INV));
        let (_, carry) = r0.mac(k, modulus[0], Limb::ZERO);
        let (r1, carry) = r1.mac(k, modulus[1], carry);
        let (r2, carry) = r2.mac(k, modulus[2], carry);
        let (r3, carry) = r3.mac(k, modulus[3], carry);
        let (r4, carry) = r4.mac(k, modulus[4], carry);
        let (r5, carry) = r5.mac(k, modulus[5], carry);
        let (r6, carry2) = r6.adc(Limb::ZERO, carry);

        let k = r1.wrapping_mul(Limb(INV));
        let (_, carry) = r1.mac(k, modulus[0], Limb::ZERO);
        let (r2, carry) = r2.mac(k, modulus[1], carry);
        let (r3, carry) = r3.mac(k, modulus[2], carry);
        let (r4, carry) = r4.mac(k, modulus[3], carry);
        let (r5, carry) = r5.mac(k, modulus[4], carry);
        let (r6, carry) = r6.mac(k, modulus[5], carry);
        let (r7, carry2) = r7.adc(carry2, carry);

        let k = r2.wrapping_mul(Limb(INV));
        let (_, carry) = r2.mac(k, modulus[0], Limb::ZERO);
        let (r3, carry) = r3.mac(k, modulus[1], carry);
        let (r4, carry) = r4.mac(k, modulus[2], carry);
        let (r5, carry) = r5.mac(k, modulus[3], carry);
        let (r6, carry) = r6.mac(k, modulus[4], carry);
        let (r7, carry) = r7.mac(k, modulus[5], carry);
        let (r8, carry2) = r8.adc(carry2, carry);

        let k = r3.wrapping_mul(Limb(INV));
        let (_, carry) = r3.mac(k, modulus[0], Limb::ZERO);
        let (r4, carry) = r4.mac(k, modulus[1], carry);
        let (r5, carry) = r5.mac(k, modulus[2], carry);
        let (r6, carry) = r6.mac(k, modulus[3], carry);
        let (r7, carry) = r7.mac(k, modulus[4], carry);
        let (r8, carry) = r8.mac(k, modulus[5], carry);
        let (r9, carry2) = r9.adc(carry2, carry);

        let k = r4.wrapping_mul(Limb(INV));
        let (_, carry) = r4.mac(k, modulus[0], Limb::ZERO);
        let (r5, carry) = r5.mac(k, modulus[1], carry);
        let (r6, carry) = r6.mac(k, modulus[2], carry);
        let (r7, carry) = r7.mac(k, modulus[3], carry);
        let (r8, carry) = r8.mac(k, modulus[4], carry);
        let (r9, carry) = r9.mac(k, modulus[5], carry);
        let (r10, carry2) = r10.adc(carry2, carry);

        let k = r5.wrapping_mul(Limb(INV));
        let (_, carry) = r5.mac(k, modulus[0], Limb::ZERO);
        let (r6, carry) = r6.mac(k, modulus[1], carry);
        let (r7, carry) = r7.mac(k, modulus[2], carry);
        let (r8, carry) = r8.mac(k, modulus[3], carry);
        let (r9, carry) = r9.mac(k, modulus[4], carry);
        let (r10, carry) = r10.mac(k, modulus[5], carry);
        let (r11, _) = r11.adc(carry2, carry);

        Self::from_uint_reduced(U384::new([r6, r7, r8, r9, r10, r11]))
    }
}

impl From<u64> for Scalar {
    fn from(n: u64) -> Scalar {
        Self(n.into())
    }
}

impl TryFrom<U384> for Scalar {
    type Error = Error;

    fn try_from(w: U384) -> Result<Self> {
        Option::from(ScalarCore::new(w)).map(Self).ok_or(Error)
    }
}

impl From<Scalar> for U384 {
    fn from(scalar: Scalar) -> U384 {
        *scalar.0.as_uint()
    }
}

impl From<ScalarCore> for Scalar {
    fn from(scalar: ScalarCore) -> Scalar {
        Self(scalar)
    }
}

impl From<Scalar> for FieldBytes {
    fn from(scalar: Scalar) -> Self {
        Self::from(&scalar)
    }
}

impl From<&Scalar> for FieldBytes {
    fn from(scalar: &Scalar) -> Self {
        scalar.to_repr()
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(ScalarCore::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl DefaultIsZeroes for Scalar {}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        self.0.is_high()
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        self.add(&other)
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Self(self.0.add(&other.0))
    }
}

impl AddAssign<Scalar> for Scalar {
    fn add_assign(&mut self, other: Scalar) {
        *self = *self + other;
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, other: &Scalar) {
        *self = *self + other;
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        self.sub(&other)
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Self(self.0.sub(&other.0))
    }
}

impl SubAssign<Scalar> for Scalar {
    fn sub_assign(&mut self, other: Scalar) {
        *self = *self - other;
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, other: &Scalar) {
        *self = *self - other;
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Self(self.0.neg())
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    #[inline]
    fn mul(self, other: &Scalar) -> Self {
        Self::mul(&self, other)
    }
}

impl Mul for Scalar {
    type Output = Scalar;

    #[allow(clippy::op_ref)]
    #[inline]
    fn mul(self, other: Scalar) -> Self {
        self * &other
    }
}

impl MulAssign<&Scalar> for Scalar {
    #[cfg(target_pointer_width = "64")]
    #[inline]
    fn mul_assign(&mut self, other: &Scalar) {
        *self = *self * other;
    }
}

impl MulAssign for Scalar {
    #[inline]
    fn mul_assign(&mut self, other: Scalar) {
        self.mul_assign(&other);
    }
}

impl Reduce<U384> for Scalar {
    fn from_uint_reduced(w: U384) -> Self {
        let (r, underflow) = w.sbb(&NistP384::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BIT_SIZE - 1)) as u8);
        let reduced = U384::conditional_select(&w, &r, !underflow);
        Self(ScalarCore::new(reduced).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::Scalar;
    use crate::FieldBytes;
    use elliptic_curve::ff::{Field, PrimeField};

    #[test]
    fn from_to_bytes_roundtrip() {
        let k: u64 = 42;
        let mut bytes = FieldBytes::default();
        bytes[40..].copy_from_slice(k.to_be_bytes().as_ref());

        let scalar = Scalar::from_repr(bytes).unwrap();
        assert_eq!(bytes, scalar.to_bytes());
    }

    /// Basic tests that multiplication works.
    #[test]
    #[ignore]
    fn multiply() {
        let one = Scalar::one();
        let two = one + &one;
        let three = two + &one;
        let six = three + &three;
        assert_eq!(six, two * &three);

        let minus_two = -two;
        let minus_three = -three;
        assert_eq!(two, -minus_two);

        assert_eq!(minus_three * &minus_two, minus_two * &minus_three);
        assert_eq!(six, minus_two * &minus_three);
    }

    /// Basic tests that scalar inversion works.
    #[test]
    #[ignore]
    fn invert() {
        let one = Scalar::one();
        let three = one + &one + &one;
        let inv_three = three.invert().unwrap();
        // println!("1/3 = {:x?}", &inv_three);
        assert_eq!(three * &inv_three, one);

        let minus_three = -three;
        // println!("-3 = {:x?}", &minus_three);
        let inv_minus_three = minus_three.invert().unwrap();
        assert_eq!(inv_minus_three, -inv_three);
        // println!("-1/3 = {:x?}", &inv_minus_three);
        assert_eq!(three * &inv_minus_three, -one);
    }

    /// Basic tests that sqrt works.
    #[test]
    #[ignore]
    fn sqrt() {
        for &n in &[1u64, 4, 9, 16, 25, 36, 49, 64] {
            let scalar = Scalar::from(n);
            let sqrt = scalar.sqrt().unwrap();
            assert_eq!(sqrt.square(), scalar);
        }
    }
}
