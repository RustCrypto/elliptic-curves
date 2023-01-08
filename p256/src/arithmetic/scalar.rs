//! Scalar field arithmetic modulo n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

pub mod blinded;

#[cfg_attr(target_pointer_width = "32", path = "scalar/scalar32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/scalar64.rs")]
mod scalar_impl;

use self::scalar_impl::barrett_reduce;
use crate::{FieldBytes, NistP256, SecretKey};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use elliptic_curve::{
    bigint::{prelude::*, Limb, U256},
    generic_array::arr,
    group::ff::{Field, PrimeField},
    ops::{Reduce, ReduceNonZero},
    rand_core::RngCore,
    subtle::{
        Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
        CtOption,
    },
    zeroize::DefaultIsZeroes,
    Curve, IsHigh, ScalarCore,
};

#[cfg(feature = "bits")]
use {crate::ScalarBits, elliptic_curve::group::ff::PrimeFieldBits};

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

/// Constant representing the modulus
/// n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
pub(crate) const MODULUS: U256 = NistP256::ORDER;

/// `MODULUS / 2`
const FRAC_MODULUS_2: Scalar = Scalar(MODULUS.shr_vartime(1));

/// MU = floor(2^512 / n)
///    = 115792089264276142090721624801893421302707618245269942344307673200490803338238
///    = 0x100000000fffffffffffffffeffffffff43190552df1a6c21012ffd85eedf9bfe
pub const MU: [u64; 5] = [
    0x012f_fd85_eedf_9bfe,
    0x4319_0552_df1a_6c21,
    0xffff_fffe_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0001,
];

/// Scalars are elements in the finite field modulo n.
///
/// # Trait impls
///
/// Much of the important functionality of scalars is provided by traits from
/// the [`ff`](https://docs.rs/ff/) crate, which is re-exported as
/// `p256::elliptic_curve::ff`:
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
///
/// # `serde` support
///
/// When the `serde` feature of this crate is enabled, the `Serialize` and
/// `Deserialize` traits are impl'd for this type.
///
/// The serialization is a fixed-width big endian encoding. When used with
/// textual formats, the binary data is encoded as hexadecimal.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
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
        Self(self.0.add_mod(&rhs.0, &NistP256::ORDER))
    }

    /// Returns 2*self.
    pub const fn double(&self) -> Self {
        self.add(self)
    }

    /// Returns self - rhs mod n.
    pub const fn sub(&self, rhs: &Self) -> Self {
        Self(self.0.sub_mod(&rhs.0, &NistP256::ORDER))
    }

    /// Returns self * rhs mod n
    pub const fn mul(&self, rhs: &Self) -> Self {
        let (lo, hi) = self.0.mul_wide(&rhs.0);
        Self(barrett_reduce(lo, hi))
    }

    /// Returns self * self mod p
    pub const fn square(&self) -> Self {
        // Schoolbook multiplication.
        self.mul(self)
    }

    /// Returns the multiplicative inverse of self, if self is non-zero
    pub fn invert(&self) -> CtOption<Self> {
        // We need to find b such that b * a ≡ 1 mod p. As we are in a prime
        // field, we can apply Fermat's Little Theorem:
        //
        //    a^p         ≡ a mod p
        //    a^(p-1)     ≡ 1 mod p
        //    a^(p-2) * a ≡ 1 mod p
        //
        // Thus inversion can be implemented with a single exponentiation.
        //
        // This is `n - 2`, so the top right two digits are `4f` instead of `51`.
        let inverse = self.pow_vartime([
            0xf3b9_cac2_fc63_254f,
            0xbce6_faad_a717_9e84,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_0000_0000,
        ]);

        CtOption::new(inverse, !self.is_zero())
    }

    /// Faster inversion using Stein's algorithm
    #[allow(non_snake_case)]
    pub fn invert_vartime(&self) -> CtOption<Self> {
        // https://link.springer.com/article/10.1007/s13389-016-0135-4

        let mut u = *self;
        // currently an invalid scalar
        let mut v = Scalar(NistP256::ORDER);
        let mut A = Self::one();
        let mut C = Self::zero();

        while !bool::from(u.is_zero()) {
            // u-loop
            while bool::from(u.is_even()) {
                u.shr1();

                let was_odd: bool = A.is_odd().into();
                A.shr1();

                if was_odd {
                    A += FRAC_MODULUS_2;
                    A += Self::one();
                }
            }

            // v-loop
            while bool::from(v.is_even()) {
                v.shr1();

                let was_odd: bool = C.is_odd().into();
                C.shr1();

                if was_odd {
                    C += FRAC_MODULUS_2;
                    C += Self::one();
                }
            }

            // sub-step
            if u >= v {
                u -= &v;
                A -= &C;
            } else {
                v -= &u;
                C -= &A;
            }
        }

        CtOption::new(C, !self.is_zero())
    }

    /// Is integer representing equivalence class odd?
    pub fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }

    /// Is integer representing equivalence class even?
    pub fn is_even(&self) -> Choice {
        !self.is_odd()
    }

    /// Shift right by one bit
    fn shr1(&mut self) {
        self.0 >>= 1;
    }
}

impl Field for Scalar {
    fn random(mut rng: impl RngCore) -> Self {
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
            rng.fill_bytes(&mut bytes);
            if let Some(scalar) = Scalar::from_repr(bytes).into() {
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

    #[must_use]
    fn square(&self) -> Self {
        Scalar::square(self)
    }

    #[must_use]
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
        // Note: `pow_vartime` is constant-time with respect to `self`
        let w = self.pow_vartime([
            0x279dce5617e3192a,
            0xfde737d56d38bcf4,
            0x07ffffffffffffff,
            0x07fffffff8000000,
        ]);

        let mut v = Self::S;
        let mut x = *self * w;
        let mut b = x * w;
        let mut z = Self::root_of_unity();

        for max_v in (1..=Self::S).rev() {
            let mut k = 1;
            let mut tmp = b.square();
            let mut j_less_than_v = Choice::from(1);

            for j in 2..max_v {
                let tmp_is_one = tmp.ct_eq(&Self::one());
                let squared = Self::conditional_select(&tmp, &z, tmp_is_one).square();
                tmp = Self::conditional_select(&squared, &tmp, tmp_is_one);
                let new_z = Self::conditional_select(&z, &squared, tmp_is_one);
                j_less_than_v &= !j.ct_eq(&v);
                k = u32::conditional_select(&j, &k, tmp_is_one);
                z = Self::conditional_select(&z, &new_z, j_less_than_v);
            }

            let result = x * z;
            x = Self::conditional_select(&result, &x, b.ct_eq(&Self::one()));
            z = z.square();
            b *= z;
            v = k;
        }

        CtOption::new(x, x.square().ct_eq(self))
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const S: u32 = 4;

    /// Attempts to parse the given byte array as an SEC1-encoded scalar.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        let inner = U256::from_be_byte_array(bytes);
        CtOption::new(Self(inner), inner.ct_lt(&NistP256::ORDER))
    }

    fn to_repr(&self) -> FieldBytes {
        self.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }

    fn multiplicative_generator() -> Self {
        7u64.into()
    }

    fn root_of_unity() -> Self {
        Scalar::from_repr(arr![u8;
            0xff, 0xc9, 0x7f, 0x06, 0x2a, 0x77, 0x09, 0x92, 0xba, 0x80, 0x7a, 0xce, 0x84, 0x2a,
            0x3d, 0xfc, 0x15, 0x46, 0xca, 0xd0, 0x04, 0x37, 0x8d, 0xaf, 0x05, 0x92, 0xd7, 0xfb,
            0xb4, 0x1e, 0x66, 0x02,
        ])
        .unwrap()
    }
}

#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
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

impl DefaultIsZeroes for Scalar {}

impl Eq for Scalar {}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        self.0.ct_gt(&FRAC_MODULUS_2.0)
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

impl From<u64> for Scalar {
    fn from(k: u64) -> Self {
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

impl From<ScalarCore<NistP256>> for Scalar {
    fn from(scalar: ScalarCore<NistP256>) -> Scalar {
        Scalar(*scalar.as_uint())
    }
}

impl From<&ScalarCore<NistP256>> for Scalar {
    fn from(scalar: &ScalarCore<NistP256>) -> Scalar {
        Scalar(*scalar.as_uint())
    }
}

impl From<Scalar> for ScalarCore<NistP256> {
    fn from(scalar: Scalar) -> ScalarCore<NistP256> {
        ScalarCore::from(&scalar)
    }
}

impl From<&Scalar> for ScalarCore<NistP256> {
    fn from(scalar: &Scalar) -> ScalarCore<NistP256> {
        ScalarCore::new(scalar.0).unwrap()
    }
}

impl From<&SecretKey> for Scalar {
    fn from(secret_key: &SecretKey) -> Scalar {
        *secret_key.to_nonzero_scalar()
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

#[cfg(feature = "bits")]
#[cfg_attr(docsrs, doc(cfg(feature = "bits")))]
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
        Scalar::mul(&self, &other)
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar::mul(self, other)
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar::mul(&self, other)
    }
}

impl MulAssign<Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = Scalar::mul(self, &rhs);
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = Scalar::mul(self, rhs);
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Scalar::zero() - self
    }
}

impl<'a> Neg for &'a Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Scalar::zero() - self
    }
}

impl Reduce<U256> for Scalar {
    fn from_uint_reduced(w: U256) -> Self {
        let (r, underflow) = w.sbb(&NistP256::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BIT_SIZE - 1)) as u8);
        Self(U256::conditional_select(&w, &r, !underflow))
    }
}

impl ReduceNonZero<U256> for Scalar {
    fn from_uint_reduced_nonzero(w: U256) -> Self {
        const ORDER_MINUS_ONE: U256 = NistP256::ORDER.wrapping_sub(&U256::ONE);
        let (r, underflow) = w.sbb(&ORDER_MINUS_ONE, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BIT_SIZE - 1)) as u8);
        Self(U256::conditional_select(&w, &r, !underflow).wrapping_add(&U256::ONE))
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(U256::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        ScalarCore::from(self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(ScalarCore::deserialize(deserializer)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::Scalar;
    use crate::{FieldBytes, SecretKey};
    use elliptic_curve::group::ff::{Field, PrimeField};

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
    fn sqrt() {
        for &n in &[1u64, 4, 9, 16, 25, 36, 49, 64] {
            let scalar = Scalar::from(n);
            let sqrt = scalar.sqrt().unwrap();
            assert_eq!(sqrt.square(), scalar);
        }
    }

    /// Tests that a Scalar can be safely converted to a SecretKey and back
    #[test]
    fn from_ec_secret() {
        let scalar = Scalar::one();
        let secret = SecretKey::from_be_bytes(&scalar.to_bytes()).unwrap();
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

        let scalar_bits = ScalarBits::from(&-Scalar::from(1));
        assert_eq!(minus_one, scalar_bits);
    }
}
