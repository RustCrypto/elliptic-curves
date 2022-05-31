//! secp384r1 scalar field elements.

#![allow(clippy::unusual_byte_groupings)]

pub(crate) mod blinded;

#[cfg_attr(target_pointer_width = "32", path = "scalar/p384_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/p384_scalar_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::too_many_arguments,
    clippy::unnecessary_cast
)]
#[allow(dead_code)]
#[rustfmt::skip]
mod scalar_impl;

use self::scalar_impl::*;
use super::LIMBS;
use crate::{FieldBytes, NistP384, SecretKey, U384};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    bigint::{ArrayEncoding, Encoding, Limb, LimbUInt as Word},
    ff::{Field, PrimeField},
    generic_array::arr,
    ops::Reduce,
    rand_core::RngCore,
    subtle::{
        Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
        CtOption,
    },
    zeroize::DefaultIsZeroes,
    Curve as _, Error, IsHigh, Result, ScalarArithmetic, ScalarCore,
};

#[cfg(feature = "bits")]
use {crate::ScalarBits, elliptic_curve::group::ff::PrimeFieldBits};

type Fe = fiat_p384_scalar_montgomery_domain_field_element;
type NonMontFe = fiat_p384_scalar_non_montgomery_domain_field_element;

fn frac_modulus_2() -> Scalar {
    Scalar::from_be_bytes(NistP384::ORDER.shr_vartime(1).to_be_bytes().into()).unwrap()
}

impl ScalarArithmetic for NistP384 {
    type Scalar = Scalar;
}

/// Scalars are elements in the finite field modulo n.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct Scalar(U384);

impl Scalar {
    /// Zero scalar.
    pub const ZERO: Self = Self(U384::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = Self(U384::from_be_hex("000000000000000000000000000000000000000000000000389cb27e0bc8d220a7e5f24db74f58851313e695333ad68d"));

    /// Create a scalar from a canonical, big-endian representation
    pub fn from_be_bytes(bytes: FieldBytes) -> CtOption<Self> {
        Self::from_uint(U384::from_be_byte_array(bytes))
    }

    /// Decode scalar from a big endian byte slice.
    pub fn from_be_slice(slice: &[u8]) -> Result<Self> {
        <U384 as Encoding>::Repr::try_from(slice)
            .ok()
            .and_then(|array| Self::from_be_bytes(array.into()).into())
            .ok_or(Error)
    }

    /// Create a scalar from a canonical, little-endian representation
    pub fn from_le_bytes(bytes: FieldBytes) -> CtOption<Self> {
        Self::from_uint(U384::from_le_byte_array(bytes))
    }

    /// Decode scalar from a little endian byte slice.
    pub fn from_le_slice(slice: &[u8]) -> Result<Self> {
        <U384 as Encoding>::Repr::try_from(slice)
            .ok()
            .and_then(|array| Self::from_le_bytes(array.into()).into())
            .ok_or(Error)
    }

    /// Decode scalar from a [`U384`].
    pub fn from_uint(w: U384) -> CtOption<Self> {
        let is_some = w.ct_lt(&NistP384::ORDER);
        let mut mont = U384::default();
        fiat_p384_scalar_to_montgomery(mont.as_mut(), w.as_ref());
        CtOption::new(Scalar(mont), is_some)
    }

    /// Returns the little-endian encoding of this scalar.
    pub fn to_be_bytes(&self) -> FieldBytes {
        self.to_non_mont().0.to_be_byte_array()
    }

    /// Returns the little-endian encoding of this scalar.
    pub fn to_le_bytes(&self) -> FieldBytes {
        self.to_non_mont().0.to_le_byte_array()
    }

    /// Returns the SEC1 encoding of this scalar.
    ///
    /// Required for running test vectors.
    #[cfg(test)]
    pub fn to_bytes(&self) -> FieldBytes {
        self.to_be_bytes()
    }

    /// Double
    pub fn double(&self) -> Self {
        let mut result = Default::default();
        fiat_p384_scalar_add(&mut result, self.as_ref(), self.as_ref());
        Self(result.into())
    }

    /// Compute modular square.
    #[must_use]
    pub fn square(&self) -> Self {
        let mut result = Default::default();
        fiat_p384_scalar_square(&mut result, self.as_ref());
        Self(result.into())
    }

    /// Invert
    pub fn invert(&self) -> CtOption<Self> {
        const ITERATIONS: usize = (49 * U384::BIT_SIZE + 57) / 17;
        type XLimbs = [Word; LIMBS + 1];

        let mut d: Word = 1;
        let mut f = XLimbs::default();
        fiat_p384_scalar_msat(&mut f);

        let mut g = XLimbs::default();
        fiat_p384_scalar_from_montgomery((&mut g[..LIMBS]).try_into().unwrap(), self.as_ref());

        let mut r = Fe::default();
        fiat_p384_scalar_set_one(&mut r);

        let mut v = Fe::default();
        let mut precomp = Fe::default();
        fiat_p384_scalar_divstep_precomp(&mut precomp);

        let mut out1 = Word::default();
        let mut out2 = XLimbs::default();
        let mut out3 = XLimbs::default();
        let mut out4 = Fe::default();
        let mut out5 = Fe::default();

        let mut i: usize = 0;

        while i < ITERATIONS - ITERATIONS % 2 {
            fiat_p384_scalar_divstep(
                &mut out1, &mut out2, &mut out3, &mut out4, &mut out5, d, &f, &g, &v, &r,
            );
            fiat_p384_scalar_divstep(
                &mut d, &mut f, &mut g, &mut v, &mut r, out1, &out2, &out3, &out4, &out5,
            );
            i += 2;
        }

        if ITERATIONS % 2 != 0 {
            fiat_p384_scalar_divstep(
                &mut out1, &mut out2, &mut out3, &mut out4, &mut out5, d, &f, &g, &v, &r,
            );
            v = out4;
            f = out2;
        }

        let mut v_opp = Fe::default();
        fiat_p384_scalar_opp(&mut v_opp, &v);

        let s = ((f[f.len() - 1] >> (Limb::BIT_SIZE - 1)) & 1) as u8;
        let mut v_ = Fe::default();
        fiat_p384_scalar_selectznz(&mut v_, s, &v, &v_opp);

        let mut ret = U384::default();
        fiat_p384_scalar_mul(ret.as_mut(), &v_, &precomp);
        CtOption::new(Self(ret), !self.is_zero())
    }

    /// Invert
    pub fn invert_vartime(&self) -> CtOption<Self> {
        self.invert()
    }

    fn sqn(&self, n: usize) -> Self {
        let mut x = *self;
        for _ in 0..n {
            x = x.square();
        }
        x
    }

    fn to_non_mont(self) -> Self {
        let mut out = Default::default();
        fiat_p384_scalar_from_montgomery(&mut out, self.as_ref());
        Scalar(out.into())
    }
}

impl AsRef<Fe> for Scalar {
    fn as_ref(&self) -> &Fe {
        self.0.as_ref()
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.0.ct_eq(&rhs.0)
    }
}

impl ConstantTimeGreater for Scalar {
    fn ct_gt(&self, other: &Self) -> Choice {
        self.0.ct_gt(&other.0)
    }
}

impl ConstantTimeLess for Scalar {
    fn ct_lt(&self, other: &Self) -> Choice {
        self.0.ct_lt(&other.0)
    }
}

impl DefaultIsZeroes for Scalar {}

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
        Self::ZERO.ct_eq(self)
    }

    #[must_use]
    fn square(&self) -> Self {
        Scalar::square(self)
    }

    #[must_use]
    fn double(&self) -> Self {
        Scalar::double(self)
    }

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }

    fn sqrt(&self) -> CtOption<Self> {
        // p mod 4 = 3 -> compute sqrt(x) using x^((p+1)/4) =
        // x^9850501549098619803069760025035903451269934817616361666986726319906914849778315892349739077038073728388608413485661
        let t1 = *self;
        let t10 = t1.square();
        let t11 = *self * t10;
        let t101 = t10 * t11;
        let t111 = t10 * t101;
        let t1001 = t10 * t111;
        let t1011 = t10 * t1001;
        let t1101 = t10 * t1011;
        let t1111 = t10 * t1101;
        let t11110 = t1111.square();
        let t11111 = t1 * t11110;
        let t1111100 = t11111.sqn(2);
        let t11111000 = t1111100.square();
        let i14 = t11111000.square();
        let i20 = i14.sqn(5) * i14;
        let i31 = i20.sqn(10) * i20;
        let i58 = (i31.sqn(4) * t11111000).sqn(21) * i31;
        let i110 = (i58.sqn(3) * t1111100).sqn(47) * i58;
        let x194 = i110.sqn(95) * i110 * t1111;
        let i225 = ((x194.sqn(6) * t111).sqn(3) * t11).sqn(7);
        let i235 = ((t1101 * i225).sqn(6) * t1101).square() * t1;
        let i258 = ((i235.sqn(11) * t11111).sqn(2) * t1).sqn(8);
        let i269 = ((t1101 * i258).sqn(2) * t11).sqn(6) * t1011;
        let i286 = ((i269.sqn(4) * t111).sqn(6) * t11111).sqn(5);
        let i308 = ((t1011 * i286).sqn(10) * t1101).sqn(9) * t1101;
        let i323 = ((i308.sqn(4) * t1011).sqn(6) * t1001).sqn(3);
        let i340 = ((t1 * i323).sqn(7) * t1011).sqn(7) * t101;
        let i357 = ((i340.sqn(5) * t111).sqn(5) * t1111).sqn(5);
        let i369 = ((t1011 * i357).sqn(4) * t1011).sqn(5) * t111;
        let i387 = ((i369.sqn(3) * t11).sqn(7) * t11).sqn(6);
        let i397 = ((t1011 * i387).sqn(4) * t101).sqn(3) * t11;
        let i413 = ((i397.sqn(4) * t11).sqn(4) * t11).sqn(6);
        let i427 = ((t101 * i413).sqn(5) * t101).sqn(6) * t1011;
        let x = i427.sqn(3) * t101;
        if x.square() == t1 {
            CtOption::new(x, 1.into())
        } else {
            CtOption::new(x, 0.into())
        }
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const CAPACITY: u32 = 383;
    const NUM_BITS: u32 = 384;
    const S: u32 = 1;

    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        Self::from_be_bytes(bytes)
    }

    fn to_repr(&self) -> FieldBytes {
        self.to_be_bytes()
    }

    fn is_odd(&self) -> Choice {
        let mut non_mont = Default::default();
        fiat_p384_scalar_from_montgomery(&mut non_mont, self.as_ref());
        let limbs = self.as_ref();
        Choice::from((limbs[limbs.len() - 1] & 1) as u8)
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

impl From<ScalarCore<NistP384>> for Scalar {
    fn from(x: ScalarCore<NistP384>) -> Self {
        Scalar::from_be_bytes(x.to_be_bytes()).unwrap()
    }
}

impl From<u64> for Scalar {
    fn from(n: u64) -> Scalar {
        let mut limbs = NonMontFe::default();

        #[cfg(target_pointer_width = "32")]
        {
            limbs[0] = (n & 0xffff_ffff) as u32;
            limbs[1] = (n >> 32) as u32;
        }

        #[cfg(target_pointer_width = "64")]
        {
            limbs[0] = n;
        }

        let mut fe = Fe::default();
        fiat_p384_scalar_to_montgomery(&mut fe, &limbs);
        Scalar(fe.into())
    }
}

impl TryFrom<U384> for Scalar {
    type Error = Error;

    fn try_from(w: U384) -> Result<Self> {
        let bytes = w.to_le_bytes();
        let mut limbs = NonMontFe::default();
        fiat_p384_scalar_from_bytes(&mut limbs, &bytes);
        Ok(Scalar(limbs.into()))
    }
}

impl From<Scalar> for U384 {
    fn from(scalar: Scalar) -> U384 {
        let bytes = scalar.to_le_bytes();
        U384::from_le_bytes(bytes.into())
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

impl From<&Scalar> for U384 {
    fn from(scalar: &Scalar) -> U384 {
        U384::from_le_bytes(scalar.to_le_bytes().into())
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = Default::default();
        fiat_p384_scalar_selectznz(&mut out, choice.unwrap_u8(), a.as_ref(), b.as_ref());
        Self(out.into())
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        self.ct_gt(&frac_modulus_2())
    }
}

impl_field_op!(Scalar, U384, Add, add, fiat_p384_scalar_add);
impl_field_op!(Scalar, U384, Sub, sub, fiat_p384_scalar_sub);
impl_field_op!(Scalar, U384, Mul, mul, fiat_p384_scalar_mul);

impl AddAssign<Scalar> for Scalar {
    #[inline]
    fn add_assign(&mut self, other: Scalar) {
        *self = *self + other;
    }
}

impl AddAssign<&Scalar> for Scalar {
    #[inline]
    fn add_assign(&mut self, other: &Scalar) {
        *self = *self + other;
    }
}

impl SubAssign<Scalar> for Scalar {
    #[inline]
    fn sub_assign(&mut self, other: Scalar) {
        *self = *self - other;
    }
}

impl SubAssign<&Scalar> for Scalar {
    #[inline]
    fn sub_assign(&mut self, other: &Scalar) {
        *self = *self - other;
    }
}

impl MulAssign<&Scalar> for Scalar {
    #[inline]
    fn mul_assign(&mut self, other: &Scalar) {
        *self = *self * other;
    }
}

impl MulAssign for Scalar {
    #[inline]
    fn mul_assign(&mut self, other: Scalar) {
        *self = *self * other;
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    #[inline]
    fn neg(self) -> Scalar {
        let mut result = Default::default();
        fiat_p384_scalar_opp(&mut result, self.as_ref());
        Self(result.into())
    }
}

impl Reduce<U384> for Scalar {
    fn from_uint_reduced(w: U384) -> Self {
        let (r, underflow) = w.sbb(&NistP384::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BIT_SIZE - 1)) as u8);
        let reduced = U384::conditional_select(&w, &r, !underflow);
        Scalar::from(ScalarCore::new(reduced).unwrap())
    }
}

#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
impl PrimeFieldBits for Scalar {
    #[cfg(target_pointer_width = "32")]
    type ReprBits = [u32; 12];
    #[cfg(target_pointer_width = "64")]
    type ReprBits = [u64; 6];

    fn to_le_bits(&self) -> ScalarBits {
        (*self.as_ref()).into()
    }

    fn char_le_bits() -> ScalarBits {
        NistP384::ORDER.to_uint_array().into()
    }
}

impl From<&ScalarCore<NistP384>> for Scalar {
    fn from(scalar: &ScalarCore<NistP384>) -> Scalar {
        Scalar::from_be_bytes(scalar.to_be_bytes()).unwrap()
    }
}

impl From<Scalar> for ScalarCore<NistP384> {
    fn from(scalar: Scalar) -> ScalarCore<NistP384> {
        ScalarCore::new(U384::from_le_bytes(scalar.to_le_bytes().into())).unwrap()
    }
}

impl From<&Scalar> for ScalarCore<NistP384> {
    fn from(scalar: &Scalar) -> ScalarCore<NistP384> {
        ScalarCore::new(U384::from_le_bytes(scalar.to_le_bytes().into())).unwrap()
    }
}

impl From<&SecretKey> for Scalar {
    fn from(secret_key: &SecretKey) -> Scalar {
        *secret_key.to_nonzero_scalar()
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::ff::{Field, PrimeField};

    use super::{fiat_p384_scalar_to_montgomery, Fe, Scalar};
    use crate::FieldBytes;

    /// Test that the precomputed `Scalar::ONE` constant is correct.
    #[test]
    fn one() {
        let mut one = Fe::default();
        one[0] = 1;

        let mut one_mont = Fe::default();
        fiat_p384_scalar_to_montgomery(&mut one_mont, &one);
        assert_eq!(Scalar(one_mont.into()), Scalar::ONE);
    }

    #[test]
    fn from_to_bytes_roundtrip() {
        let k: u64 = 42;
        let mut bytes = FieldBytes::default();
        bytes[40..].copy_from_slice(k.to_le_bytes().as_ref());

        let scalar = Scalar::from_repr(bytes).unwrap();
        assert_eq!(bytes, scalar.to_be_bytes());
    }

    /// Basic tests that multiplication works.
    #[test]
    fn multiply() {
        let one = Scalar::one();
        let two = one + one;
        let three = two + one;
        let six = three + three;
        assert_eq!(six, two * three);

        let minus_two = -two;
        let minus_three = -three;
        assert_eq!(two, -minus_two);

        assert_eq!(minus_three * minus_two, minus_two * minus_three);
        assert_eq!(six, minus_two * minus_three);
    }

    /// Basic tests that scalar inversion works.
    #[test]
    fn invert() {
        let one = Scalar::one();
        let three = one + one + one;
        let inv_three = three.invert().unwrap();
        assert_eq!(three * inv_three, one);

        let minus_three = -three;
        let inv_minus_three = minus_three.invert().unwrap();
        assert_eq!(inv_minus_three, -inv_three);
        assert_eq!(three * inv_minus_three, -one);
    }

    /// Basic tests that sqrt works.
    #[test]
    fn sqrt() {
        for &n in &[1u64, 4, 9, 16, 25, 36, 49, 64] {
            let scalar = Scalar::from(n);
            let sqrt = scalar.sqrt().unwrap();
            assert_eq!(sqrt.square(), scalar);
        }
    }
}
