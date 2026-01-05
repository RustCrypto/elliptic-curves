//! Scalar field arithmetic modulo n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

#[cfg_attr(target_pointer_width = "32", path = "scalar/scalar32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/scalar64.rs")]
mod scalar_impl;

use self::scalar_impl::barrett_reduce;
use crate::{FieldBytes, NistP256, ORDER_HEX};
use core::{
    fmt::{self, Debug},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Shr, ShrAssign, Sub, SubAssign},
};
use elliptic_curve::{
    Curve,
    bigint::{ArrayEncoding, Integer, Limb, Odd, U256, Uint, modular::Retrieve},
    ctutils,
    group::ff::{self, Field, FromUniformBytes, PrimeField},
    ops::{Invert, Reduce, ReduceNonZero},
    rand_core::TryRngCore,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{
        Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
        CtOption,
    },
    zeroize::DefaultIsZeroes,
};

#[cfg(feature = "bits")]
use {crate::ScalarBits, elliptic_curve::group::ff::PrimeFieldBits};

#[cfg(feature = "serde")]
use {
    elliptic_curve::ScalarValue,
    serdect::serde::{Deserialize, Serialize, de, ser},
};

/// Constant representing the modulus
/// n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
pub(crate) const MODULUS: Odd<U256> = NistP256::ORDER;

/// `MODULUS / 2`
const FRAC_MODULUS_2: Scalar = Scalar(MODULUS.as_ref().shr_vartime(1));

#[doc = primefield::monty_field_element_doc!("Scalars are elements in the finite field modulo n.")]
#[derive(Clone, Copy, Default)]
pub struct Scalar(pub(crate) U256);

impl Scalar {
    /// Zero scalar.
    pub const ZERO: Self = Self(U256::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = Self(U256::ONE);

    /// Returns the SEC1 encoding of this scalar.
    pub fn to_bytes(&self) -> FieldBytes {
        self.0.to_be_byte_array()
    }

    /// Returns self + rhs mod n
    pub const fn add(&self, rhs: &Self) -> Self {
        Self(self.0.add_mod(&rhs.0, NistP256::ORDER.as_nz_ref()))
    }

    /// Returns 2*self.
    pub const fn double(&self) -> Self {
        self.add(self)
    }

    /// Returns self - rhs mod n.
    pub const fn sub(&self, rhs: &Self) -> Self {
        Self(self.0.sub_mod(&rhs.0, NistP256::ORDER.as_nz_ref()))
    }

    /// Returns self * rhs mod n
    pub const fn multiply(&self, rhs: &Self) -> Self {
        let (lo, hi) = self.0.widening_mul(&rhs.0);
        Self(barrett_reduce(lo, hi))
    }

    /// Returns self * self mod p
    pub const fn square(&self) -> Self {
        // Schoolbook multiplication.
        self.multiply(self)
    }

    /// Right shifts the scalar.
    ///
    /// Note: not constant-time with respect to the `shift` parameter.
    pub const fn shr_vartime(&self, shift: u32) -> Scalar {
        Self(self.0.wrapping_shr_vartime(shift))
    }

    /// Compute [`FieldElement`] inversion: `1 / self`.
    pub fn invert(&self) -> CtOption<Self> {
        self.0
            .invert_odd_mod(const { &Odd::from_be_hex(ORDER_HEX) })
            .map(Self)
            .into()
    }

    /// Compute [`FieldElement`] inversion: `1 / self` in variable-time.
    pub fn invert_vartime(&self) -> CtOption<Self> {
        self.0
            .invert_odd_mod_vartime(const { &Odd::from_be_hex(ORDER_HEX) })
            .map(Self)
            .into()
    }

    /// Returns the multiplicative inverse of self.
    ///
    /// # Panics
    /// Will panic in the event `self` is zero
    const fn invert_unwrap(&self) -> Self {
        Self(
            self.0
                .invert_odd_mod(const { &Odd::from_be_hex(ORDER_HEX) })
                .expect_copied("input should be non-zero"),
        )
    }

    /// Returns `self^exp`, where `exp` is a little-endian integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent `exp`.**
    ///
    /// If the exponent is fixed, this operation is constant time.
    pub const fn pow_vartime<const RHS_LIMBS: usize>(&self, exp: &Uint<RHS_LIMBS>) -> Self {
        let mut res = Self::ONE;
        let mut i = RHS_LIMBS;

        while i > 0 {
            i -= 1;

            let mut j = Limb::BITS;
            while j > 0 {
                j -= 1;
                res = res.square();

                if ((exp.as_limbs()[i].0 >> j) & 1) == 1 {
                    res = res.multiply(self);
                }
            }
        }

        res
    }

    /// Returns `self^(2^n) mod p`.
    ///
    /// **This operation is variable time with respect to the exponent `n`.**
    ///
    /// If the exponent is fixed, this operation is constant time.
    pub const fn sqn_vartime(&self, n: usize) -> Self {
        let mut x = *self;
        let mut i = 0;
        while i < n {
            x = x.square();
            i += 1;
        }
        x
    }

    /// Is integer representing equivalence class odd?
    pub fn is_odd(&self) -> Choice {
        self.0.is_odd().into()
    }

    /// Is integer representing equivalence class even?
    pub fn is_even(&self) -> Choice {
        !self.is_odd()
    }
}

elliptic_curve::scalar_impls!(NistP256, Scalar);

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl Field for Scalar {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    fn try_from_rng<R: TryRngCore + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut bytes = FieldBytes::default();

        // Generate a uniformly random scalar using rejection sampling,
        // which produces a uniformly random distribution of scalars.
        //
        // This method is not constant time, but should be secure so long as
        // rejected RNG outputs are unrelated to future ones (which is a
        // necessary property of a `CryptoRng`).
        //
        // With an unbiased RNG, the probability of failing to complete after 4
        // iterations is vanishingly small.
        loop {
            rng.try_fill_bytes(&mut bytes)?;
            if let Some(scalar) = Scalar::from_repr(bytes).into() {
                return Ok(scalar);
            }
        }
    }

    fn square(&self) -> Self {
        Scalar::square(self)
    }

    fn double(&self) -> Self {
        self.add(self)
    }

    fn invert(&self) -> CtOption<Self> {
        Scalar::invert(self)
    }

    /// Tonelli-Shank's algorithm for q mod 16 = 1
    /// <https://eprint.iacr.org/2012/685.pdf> (page 12, algorithm 5)
    #[allow(clippy::many_single_char_names)]
    fn sqrt(&self) -> CtOption<Self> {
        const EXP: U256 =
            U256::from_be_hex("07fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a");

        // Note: `pow_vartime` is constant-time with respect to `self`
        let w = self.pow_vartime(&EXP);

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
                j_less_than_v &= !ConstantTimeEq::ct_eq(&j, &v);
                k = u32::conditional_select(&j, &k, tmp_is_one);
                z = Self::conditional_select(&z, &new_z, j_less_than_v);
            }

            let result = x * z;
            x = Self::conditional_select(&result, &x, b.ct_eq(&Self::ONE));
            z = z.square();
            b *= z;
            v = k;
        }

        CtOption::new(x, x.square().ct_eq(self))
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        ff::helpers::sqrt_ratio_generic(num, div)
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const MODULUS: &'static str = ORDER_HEX;
    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const TWO_INV: Self = Self(U256::from_u8(2)).invert_unwrap();
    const MULTIPLICATIVE_GENERATOR: Self = Self(U256::from_u8(7));
    const S: u32 = 4;
    const ROOT_OF_UNITY: Self = Self(U256::from_be_hex(
        "ffc97f062a770992ba807ace842a3dfc1546cad004378daf0592d7fbb41e6602",
    ));
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unwrap();
    const DELTA: Self = Self(U256::from_u64(33232930569601));

    /// Attempts to parse the given byte array as an SEC1-encoded scalar.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        let inner = U256::from_be_byte_array(bytes);
        CtOption::new(
            Self(inner),
            ConstantTimeLess::ct_lt(&inner, &NistP256::ORDER),
        )
    }

    fn to_repr(&self) -> FieldBytes {
        self.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd().into()
    }
}

#[cfg(feature = "bits")]
impl PrimeFieldBits for Scalar {
    #[cfg(target_pointer_width = "32")]
    type ReprBits = [u32; 8];

    #[cfg(target_pointer_width = "64")]
    type ReprBits = [u64; 4];

    fn to_le_bits(&self) -> ScalarBits {
        self.into()
    }

    fn char_le_bits() -> ScalarBits {
        NistP256::ORDER.to_words().into()
    }
}

impl Retrieve for Scalar {
    type Output = U256;

    fn retrieve(&self) -> U256 {
        self.0
    }
}

impl DefaultIsZeroes for Scalar {}

impl Eq for Scalar {}

impl FromUintUnchecked for Scalar {
    type Uint = U256;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self(uint)
    }
}

impl Invert for Scalar {
    type Output = CtOption<Self>;

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }

    fn invert_vartime(&self) -> CtOption<Self> {
        self.invert_vartime()
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        ConstantTimeGreater::ct_gt(&self.0, &FRAC_MODULUS_2.0)
    }
}

impl Shr<usize> for Scalar {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        self.shr_vartime(rhs as u32)
    }
}

impl Shr<usize> for &Scalar {
    type Output = Scalar;

    fn shr(self, rhs: usize) -> Self::Output {
        self.shr_vartime(rhs as u32)
    }
}

impl ShrAssign<usize> for Scalar {
    fn shr_assign(&mut self, rhs: usize) {
        *self = *self >> rhs;
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl PartialOrd for Scalar {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Scalar {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl From<u32> for Scalar {
    fn from(k: u32) -> Self {
        Scalar(k.into())
    }
}

impl From<u64> for Scalar {
    fn from(k: u64) -> Self {
        Scalar(k.into())
    }
}

impl From<u128> for Scalar {
    fn from(k: u128) -> Self {
        Scalar(k.into())
    }
}

impl From<Scalar> for FieldBytes {
    fn from(scalar: Scalar) -> Self {
        scalar.to_bytes()
    }
}

impl From<&Scalar> for FieldBytes {
    fn from(scalar: &Scalar) -> Self {
        scalar.to_bytes()
    }
}

impl From<Scalar> for U256 {
    fn from(scalar: Scalar) -> U256 {
        scalar.0
    }
}

impl From<&Scalar> for U256 {
    fn from(scalar: &Scalar) -> U256 {
        scalar.0
    }
}

impl FromUniformBytes<64> for Scalar {
    fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        Self(barrett_reduce(
            U256::from_be_slice(&bytes[32..]),
            U256::from_be_slice(&bytes[..32]),
        ))
    }
}

#[cfg(feature = "bits")]
impl From<&Scalar> for ScalarBits {
    fn from(scalar: &Scalar) -> ScalarBits {
        scalar.0.to_words().into()
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        Scalar::add(&self, &other)
    }
}

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar::add(self, other)
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar::add(&self, other)
    }
}

impl AddAssign<Scalar> for Scalar {
    fn add_assign(&mut self, rhs: Scalar) {
        *self = Scalar::add(self, &rhs);
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, rhs: &Scalar) {
        *self = Scalar::add(self, rhs);
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        Scalar::sub(&self, &other)
    }
}

impl Sub<&Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Scalar::sub(self, other)
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Scalar::sub(&self, other)
    }
}

impl SubAssign<Scalar> for Scalar {
    fn sub_assign(&mut self, rhs: Scalar) {
        *self = Scalar::sub(self, &rhs);
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, rhs: &Scalar) {
        *self = Scalar::sub(self, rhs);
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Scalar {
        Scalar::multiply(&self, &other)
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar::multiply(self, other)
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar::multiply(&self, other)
    }
}

impl MulAssign<Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = Scalar::multiply(self, &rhs);
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = Scalar::multiply(self, rhs);
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Scalar::ZERO - self
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Scalar::ZERO - self
    }
}

impl Reduce<U256> for Scalar {
    fn reduce(w: &U256) -> Self {
        let (r, underflow) = w.borrowing_sub(&NistP256::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self(U256::conditional_select(w, &r, !underflow))
    }
}

impl Reduce<FieldBytes> for Scalar {
    #[inline]
    fn reduce(bytes: &FieldBytes) -> Self {
        Self::reduce(&U256::from_be_byte_array(*bytes))
    }
}

impl ReduceNonZero<U256> for Scalar {
    fn reduce_nonzero(w: &U256) -> Self {
        const ORDER_MINUS_ONE: U256 = NistP256::ORDER.as_ref().wrapping_sub(&U256::ONE);
        let (r, underflow) = w.borrowing_sub(&ORDER_MINUS_ONE, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self(U256::conditional_select(w, &r, !underflow).wrapping_add(&U256::ONE))
    }
}

impl ReduceNonZero<FieldBytes> for Scalar {
    #[inline]
    fn reduce_nonzero(bytes: &FieldBytes) -> Self {
        Self::reduce_nonzero(&U256::from_be_byte_array(*bytes))
    }
}

impl Sum for Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Add::add).unwrap_or(Self::ZERO)
    }
}

impl<'a> Sum<&'a Scalar> for Scalar {
    fn sum<I: Iterator<Item = &'a Scalar>>(iter: I) -> Self {
        iter.copied().sum()
    }
}

impl Product for Scalar {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Mul::mul).unwrap_or(Self::ONE)
    }
}

impl<'a> Product<&'a Scalar> for Scalar {
    fn product<I: Iterator<Item = &'a Scalar>>(iter: I) -> Self {
        iter.copied().product()
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(U256::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(&self.0, &other.0)
    }
}

impl ctutils::CtEq for Scalar {
    fn ct_eq(&self, other: &Self) -> ctutils::Choice {
        ConstantTimeEq::ct_eq(self, other).into()
    }
}

impl ctutils::CtSelect for Scalar {
    fn ct_select(&self, other: &Self, choice: ctutils::Choice) -> Self {
        ConditionallySelectable::conditional_select(self, other, choice.into())
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scalar(0x{:X})", &self.0)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        ScalarValue::from(self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(ScalarValue::deserialize(deserializer)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, U256};
    use crate::{FieldBytes, NistP256, NonZeroScalar, SecretKey};
    use elliptic_curve::{
        Curve,
        array::Array,
        group::ff::PrimeField,
        ops::{BatchInvert, ReduceNonZero},
    };
    use proptest::{prelude::any, prop_compose, proptest};

    primefield::test_primefield!(Scalar, U256);

    #[test]
    fn from_to_bytes_roundtrip() {
        let k: u64 = 42;
        let mut bytes = FieldBytes::default();
        bytes[24..].copy_from_slice(k.to_be_bytes().as_ref());

        let scalar = Scalar::from_repr(bytes).unwrap();
        assert_eq!(bytes, scalar.to_bytes());
    }

    /// Basic tests that multiplication works.
    #[test]
    fn multiply() {
        let one = Scalar::ONE;
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

    /// Tests that a Scalar can be safely converted to a SecretKey and back
    #[test]
    fn from_ec_secret() {
        let scalar = Scalar::ONE;
        let secret = SecretKey::from_bytes(&scalar.to_bytes()).unwrap();
        let rederived_scalar = Scalar::from(&secret);
        assert_eq!(scalar.0, rederived_scalar.0);
    }

    #[test]
    #[cfg(all(feature = "bits", target_pointer_width = "32"))]
    fn scalar_into_scalarbits() {
        use crate::ScalarBits;

        let minus_one = ScalarBits::from([
            0xfc63_2550,
            0xf3b9_cac2,
            0xa717_9e84,
            0xbce6_faad,
            0xffff_ffff,
            0xffff_ffff,
            0x0000_0000,
            0xffff_ffff,
        ]);

        let scalar_bits = ScalarBits::from(&-Scalar::from(1u32));
        assert_eq!(minus_one, scalar_bits);
    }

    #[test]
    fn reduce_nonzero() {
        assert_eq!(Scalar::reduce_nonzero(&Array::default()).0, U256::ONE,);
        assert_eq!(Scalar::reduce_nonzero(&U256::ONE).0, U256::from_u8(2),);
        assert_eq!(
            Scalar::reduce_nonzero(&U256::from_u8(2)).0,
            U256::from_u8(3),
        );

        assert_eq!(
            Scalar::reduce_nonzero(NistP256::ORDER.as_ref()).0,
            U256::from_u8(2),
        );
        assert_eq!(
            Scalar::reduce_nonzero(&NistP256::ORDER.wrapping_sub(&U256::from_u8(1))).0,
            U256::ONE,
        );
        assert_eq!(
            Scalar::reduce_nonzero(&NistP256::ORDER.wrapping_sub(&U256::from_u8(2))).0,
            NistP256::ORDER.wrapping_sub(&U256::ONE),
        );
        assert_eq!(
            Scalar::reduce_nonzero(&NistP256::ORDER.wrapping_sub(&U256::from_u8(3))).0,
            NistP256::ORDER.wrapping_sub(&U256::from_u8(2)),
        );

        assert_eq!(
            Scalar::reduce_nonzero(&NistP256::ORDER.wrapping_add(&U256::ONE)).0,
            U256::from_u8(3),
        );
        assert_eq!(
            Scalar::reduce_nonzero(&NistP256::ORDER.wrapping_add(&U256::from_u8(2))).0,
            U256::from_u8(4),
        );
    }

    prop_compose! {
        fn non_zero_scalar()(bytes in any::<[u8; 32]>()) -> NonZeroScalar {
            NonZeroScalar::reduce_nonzero(&FieldBytes::from(bytes))
        }
    }

    // TODO: move to `primefield::test_field_invert`.
    proptest! {
        #[test]
        fn batch_invert(
            a in non_zero_scalar(),
            b in non_zero_scalar(),
            c in non_zero_scalar(),
            d in non_zero_scalar(),
            e in non_zero_scalar(),
        ) {
            let scalars: [Scalar; 5] = [*a, *b, *c, *d, *e];

            let inverted_scalars = Scalar::batch_invert(scalars).unwrap();

            for (scalar, inverted_scalar) in scalars.into_iter().zip(inverted_scalars) {
                assert_eq!(inverted_scalar, scalar.invert().unwrap());
            }
        }
    }
}
