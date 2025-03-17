use crate::*;

use core::fmt::{Display, Formatter, Result as FmtResult};
use core::iter::{Product, Sum};
use core::ops::{
    Add, AddAssign, Index, IndexMut, Mul, MulAssign, Neg, Shr, ShrAssign, Sub, SubAssign,
};
use crypto_bigint::Zero;
use elliptic_curve::{
    bigint::{Encoding, Limb, NonZero, U448, U704, U896},
    ff::{helpers, Field, FieldBits, PrimeFieldBits},
    generic_array::{
        typenum::{U114, U57, U84, U88},
        GenericArray,
    },
    hash2curve::{ExpandMsg, Expander, FromOkm},
    ops::{Invert, Reduce, ReduceNonZero},
    scalar::{FromUintUnchecked, IsHigh, ScalarPrimitive},
    PrimeField,
};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption};

/// This is the scalar field
/// size = 4q = 2^446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
/// We can therefore use 14 saturated 32-bit limbs
#[derive(Debug, Copy, Clone, PartialOrd, Ord)]
pub struct Scalar(pub(crate) U448);

/// The number of bytes needed to represent the scalar field
pub type ScalarBytes = GenericArray<u8, U57>;
/// The number of bytes needed to represent the safely create a scalar from a random bytes
pub type WideScalarBytes = GenericArray<u8, U114>;

/// The order of the scalar field
pub const ORDER: U448 = U448::from_be_hex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3");
const ORDER_MINUS_ONE: U448 = ORDER.wrapping_sub(&U448::ONE);
const HALF_ORDER: U448 = ORDER.shr_vartime(1);
/// The wide order of the scalar field
pub const WIDE_ORDER: U896 = U896::from_be_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3");
const WIDE_ORDER_MINUS_ONE: U896 = WIDE_ORDER.wrapping_sub(&U896::ONE);

/// The modulus of the scalar field as a sequence of 14 32-bit limbs
pub const MODULUS_LIMBS: [u32; 14] = [
    0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272, 0xaed63690, 0xc44edb49, 0x7cca23e9, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff,
];

impl Display for Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let bytes = self.to_bytes_rfc_8032();
        for b in &bytes {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(U448::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Scalar) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Scalar {}

impl From<u8> for Scalar {
    fn from(a: u8) -> Self {
        Scalar(U448::from_u8(a))
    }
}

impl From<u16> for Scalar {
    fn from(a: u16) -> Self {
        Scalar(U448::from_u16(a))
    }
}

impl From<u32> for Scalar {
    fn from(a: u32) -> Scalar {
        Scalar(U448::from_u32(a))
    }
}

impl From<u64> for Scalar {
    fn from(a: u64) -> Self {
        Scalar(U448::from_u64(a))
    }
}

impl From<u128> for Scalar {
    fn from(a: u128) -> Self {
        Scalar(U448::from_u128(a))
    }
}

impl Index<usize> for Scalar {
    type Output = crypto_bigint::Word;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0.as_words()[index]
    }
}

impl IndexMut<usize> for Scalar {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0.as_words_mut()[index]
    }
}

// Trait implementations
impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, rhs: &Scalar) -> Self::Output {
        self.addition(rhs)
    }
}

define_add_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, rhs: &Scalar) {
        *self = *self + rhs
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        self.multiply(rhs)
    }
}

define_mul_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl MulAssign for Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = *self * rhs
    }
}

impl Sub<&Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, rhs: &Scalar) -> Self::Output {
        self.subtract(rhs)
    }
}

define_sub_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl SubAssign for Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, rhs: &Scalar) {
        *self = *self - rhs
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Self::Output {
        -&self
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Self::Output {
        Scalar::ZERO - self
    }
}

impl Default for Scalar {
    fn default() -> Scalar {
        Scalar::ZERO
    }
}

impl Sum for Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut acc = Scalar::ZERO;
        for s in iter {
            acc += s;
        }
        acc
    }
}

impl<'a> Sum<&'a Scalar> for Scalar {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let mut acc = Scalar::ZERO;
        for s in iter {
            acc += s;
        }
        acc
    }
}

impl Product for Scalar {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut acc = Scalar::ONE;
        for s in iter {
            acc *= s;
        }
        acc
    }
}

impl<'a> Product<&'a Scalar> for Scalar {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let mut acc = Scalar::ONE;
        for s in iter {
            acc *= s;
        }
        acc
    }
}

impl Field for Scalar {
    const ONE: Self = Self::ONE;
    const ZERO: Self = Self::ZERO;

    fn random(mut rng: impl RngCore) -> Self {
        let mut seed = WideScalarBytes::default();
        rng.fill_bytes(&mut seed);
        Scalar::from_bytes_mod_order_wide(&seed)
    }

    fn square(&self) -> Self {
        self.square()
    }

    fn double(&self) -> Self {
        self + self
    }

    fn invert(&self) -> CtOption<Self> {
        CtOption::new(self.invert(), !self.ct_eq(&Self::ZERO))
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        helpers::sqrt_ratio_generic(num, div)
    }
}

impl PrimeField for Scalar {
    type Repr = ScalarBytes;

    const CAPACITY: u32 = Self::NUM_BITS - 1;
    const DELTA: Self = Self(U448::from_u8(49));
    const MODULUS: &'static str = "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3";
    const MULTIPLICATIVE_GENERATOR: Self = Self(U448::from_u8(7));
    const NUM_BITS: u32 = 448;
    const ROOT_OF_UNITY: Self = Self(U448::from_be_hex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2"));
    const ROOT_OF_UNITY_INV: Self = Self(U448::from_be_hex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2"));
    const S: u32 = 1;
    const TWO_INV: Self = Self(U448::from_be_hex("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffbe6511f4e2276da4d76b1b4810b6613946e2c7aa91bc614955ac227a"));

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        Self::from_canonical_bytes(&repr)
    }

    fn to_repr(&self) -> Self::Repr {
        self.to_bytes_rfc_8032()
    }

    fn is_odd(&self) -> Choice {
        Choice::from((self.0.to_words()[0] & 1) as u8)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl From<Scalar> for Vec<u8> {
    fn from(scalar: Scalar) -> Vec<u8> {
        Self::from(&scalar)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl From<&Scalar> for Vec<u8> {
    fn from(scalar: &Scalar) -> Vec<u8> {
        scalar.to_bytes_rfc_8032().to_vec()
    }
}

impl From<Scalar> for ScalarBytes {
    fn from(scalar: Scalar) -> ScalarBytes {
        Self::from(&scalar)
    }
}

impl From<&Scalar> for ScalarBytes {
    fn from(scalar: &Scalar) -> ScalarBytes {
        scalar.to_bytes_rfc_8032()
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<Vec<u8>> for Scalar {
    type Error = &'static str;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&bytes[..])
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<&Vec<u8>> for Scalar {
    type Error = &'static str;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&bytes[..])
    }
}

impl TryFrom<&[u8]> for Scalar {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 57 {
            return Err("invalid byte length");
        }
        let scalar_bytes = ScalarBytes::clone_from_slice(bytes);
        Option::<Scalar>::from(Scalar::from_canonical_bytes(&scalar_bytes))
            .ok_or("scalar was not canonically encoded")
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<Box<[u8]>> for Scalar {
    type Error = &'static str;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

#[cfg(feature = "serde")]
impl serdect::serde::Serialize for Scalar {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.to_bytes(), s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serdect::serde::Deserialize<'de> for Scalar {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let mut buffer = ScalarBytes::default();
        serdect::array::deserialize_hex_or_bin(&mut buffer[..56], d)?;
        Option::from(Self::from_canonical_bytes(&buffer)).ok_or(serdect::serde::de::Error::custom(
            "scalar was not canonically encoded",
        ))
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for Scalar {}

impl core::fmt::LowerHex for Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let tmp = self.to_bytes_rfc_8032();
        for &b in tmp.iter() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl core::fmt::UpperHex for Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let tmp = self.to_bytes_rfc_8032();
        for &b in tmp.iter() {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl FromOkm for Scalar {
    type Length = U84;

    fn from_okm(data: &GenericArray<u8, Self::Length>) -> Self {
        const SEMI_WIDE_MODULUS: NonZero<U704> = NonZero::from_uint(U704::from_be_hex("00000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"));
        let mut tmp = GenericArray::<u8, U88>::default();
        tmp[4..].copy_from_slice(&data[..]);

        let mut num = U704::from_be_slice(&tmp[..]);
        num %= SEMI_WIDE_MODULUS;
        let mut words = [0; U448::LIMBS];
        words.copy_from_slice(&num.to_words()[..U448::LIMBS]);
        Scalar(U448::from_words(words))
    }
}

impl Reduce<U448> for Scalar {
    type Bytes = ScalarBytes;

    fn reduce(bytes: U448) -> Self {
        let (r, underflow) = bytes.sbb(&ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self(U448::conditional_select(&bytes, &r, !underflow))
    }

    fn reduce_bytes(bytes: &Self::Bytes) -> Self {
        Self::reduce(U448::from_le_slice(bytes))
    }
}

impl Reduce<U896> for Scalar {
    type Bytes = WideScalarBytes;

    fn reduce(bytes: U896) -> Self {
        let (r, underflow) = bytes.sbb(&WIDE_ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self(U896::conditional_select(&bytes, &r, !underflow).split().1)
    }

    fn reduce_bytes(bytes: &Self::Bytes) -> Self {
        Self::from_bytes_mod_order_wide(bytes)
    }
}

impl ReduceNonZero<U448> for Scalar {
    fn reduce_nonzero(bytes: U448) -> Self {
        let (r, underflow) = bytes.sbb(&ORDER_MINUS_ONE, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self(U448::conditional_select(&bytes, &r, !underflow).wrapping_add(&U448::ONE))
    }

    fn reduce_nonzero_bytes(bytes: &Self::Bytes) -> Self {
        Self::reduce_nonzero(U448::from_le_slice(bytes))
    }
}

impl ReduceNonZero<U896> for Scalar {
    fn reduce_nonzero(bytes: U896) -> Self {
        let (r, underflow) = bytes.sbb(&WIDE_ORDER_MINUS_ONE, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);

        Self(
            U896::conditional_select(&bytes, &r, !underflow)
                .split()
                .1
                .wrapping_add(&U448::ONE),
        )
    }

    fn reduce_nonzero_bytes(bytes: &Self::Bytes) -> Self {
        Self::reduce_nonzero(U896::from_le_slice(bytes))
    }
}

impl PrimeFieldBits for Scalar {
    type ReprBits = [crypto_bigint::Word; U448::LIMBS];

    fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
        self.0.to_words().into()
    }

    fn char_le_bits() -> FieldBits<Self::ReprBits> {
        ORDER.to_words().into()
    }
}

impl From<ScalarPrimitive<Ed448>> for Scalar {
    fn from(scalar: ScalarPrimitive<Ed448>) -> Self {
        Self(*scalar.as_uint())
    }
}

impl From<&ScalarPrimitive<Ed448>> for Scalar {
    fn from(scalar: &ScalarPrimitive<Ed448>) -> Self {
        let uint = *scalar.as_uint();
        uint.into()
    }
}

impl From<Scalar> for ScalarPrimitive<Ed448> {
    fn from(scalar: Scalar) -> Self {
        let uint: U448 = scalar.into();
        Self::from_uint_unchecked(uint)
    }
}

impl From<&Scalar> for ScalarPrimitive<Ed448> {
    fn from(scalar: &Scalar) -> Self {
        let uint: U448 = scalar.into();
        ScalarPrimitive::from_uint_unchecked(uint)
    }
}

impl From<ScalarPrimitive<Decaf448>> for Scalar {
    fn from(scalar: ScalarPrimitive<Decaf448>) -> Self {
        Self(*scalar.as_uint())
    }
}

impl From<&ScalarPrimitive<Decaf448>> for Scalar {
    fn from(scalar: &ScalarPrimitive<Decaf448>) -> Self {
        let uint = *scalar.as_uint();
        uint.into()
    }
}

impl From<Scalar> for ScalarPrimitive<Decaf448> {
    fn from(scalar: Scalar) -> Self {
        let uint: U448 = scalar.into();
        Self::from_uint_unchecked(uint)
    }
}

impl From<&Scalar> for ScalarPrimitive<Decaf448> {
    fn from(scalar: &Scalar) -> Self {
        let uint: U448 = scalar.into();
        ScalarPrimitive::from_uint_unchecked(uint)
    }
}

impl From<U448> for Scalar {
    fn from(uint: U448) -> Self {
        <Self as Reduce<U448>>::reduce(uint)
    }
}

impl From<&U448> for Scalar {
    fn from(uint: &U448) -> Self {
        Self::from(*uint)
    }
}

impl From<Scalar> for U448 {
    fn from(scalar: Scalar) -> Self {
        scalar.0
    }
}

impl From<&Scalar> for U448 {
    fn from(scalar: &Scalar) -> Self {
        Self::from(*scalar)
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U448;

    fn from_uint_unchecked(uint: U448) -> Self {
        Self(uint)
    }
}

impl Invert for Scalar {
    type Output = CtOption<Self>;

    fn invert(&self) -> CtOption<Self> {
        CtOption::new(self.invert(), !self.ct_eq(&Self::ZERO))
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        self.0.ct_gt(&HALF_ORDER)
    }
}

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl Shr<usize> for Scalar {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        let mut cp = self;
        cp.shr_assign(rhs);
        cp
    }
}

impl Shr<usize> for &Scalar {
    type Output = Scalar;

    fn shr(self, rhs: usize) -> Self::Output {
        let mut cp = *self;
        cp.shr_assign(rhs);
        cp
    }
}

impl ShrAssign<usize> for Scalar {
    fn shr_assign(&mut self, shift: usize) {
        self.0 >>= shift;
    }
}

#[cfg(feature = "zeroize")]
impl From<&Scalar> for Ed448ScalarBits {
    fn from(scalar: &Scalar) -> Self {
        scalar.0.to_words().into()
    }
}

impl Scalar {
    /// The multiplicative identity element
    pub const ONE: Scalar = Scalar(U448::ONE);
    /// Twice the multiplicative identity element
    pub const TWO: Scalar = Scalar(U448::from_u8(2));
    /// The additive identity element
    pub const ZERO: Scalar = Scalar(U448::ZERO);

    /// Compute `self` + `rhs` mod ℓ
    pub const fn addition(&self, rhs: &Self) -> Self {
        Self(self.0.add_mod(&rhs.0, &ORDER))
    }

    /// Compute `self` + `self` mod ℓ
    pub const fn double(&self) -> Self {
        self.addition(self)
    }

    /// Compute `self` - `rhs` mod ℓ
    pub const fn subtract(&self, rhs: &Self) -> Self {
        Self(self.0.sub_mod(&rhs.0, &ORDER))
    }

    /// Compute `self` * `rhs` mod ℓ
    pub const fn multiply(&self, rhs: &Self) -> Self {
        let wide_value = self.0.mul_wide(&rhs.0);
        Self(U448::const_rem_wide(wide_value, &ORDER).0)
    }

    /// Square this scalar
    pub const fn square(&self) -> Self {
        let value = self.0.square_wide();
        Self(U448::const_rem_wide(value, &ORDER).0)
    }

    /// Is this scalar equal to zero?
    pub fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    /// Divides a scalar by four without reducing mod p
    /// This is used in the 2-isogeny when mapping points from Ed448-Goldilocks
    /// to Twisted-Goldilocks
    pub(crate) fn div_by_four(&mut self) {
        self.0 >>= 2;
    }

    // This method was modified from Curve25519-Dalek codebase. [scalar.rs]
    // We start with 14 u32s and convert them to 56 u8s.
    // We then use the code copied from Dalek to convert the 56 u8s to radix-16 and re-center the coefficients to be between [-16,16)
    // XXX: We can recode the scalar without converting it to bytes, will refactor this method to use this and check which is faster.
    pub(crate) fn to_radix_16(self) -> [i8; 113] {
        let bytes = self.to_bytes();
        let mut output = [0i8; 113];

        // Step 1: change radix.
        // Convert from radix 256 (bytes) to radix 16 (nibbles)
        #[inline(always)]
        fn bot_half(x: u8) -> u8 {
            x & 15
        }
        #[inline(always)]
        fn top_half(x: u8) -> u8 {
            (x >> 4) & 15
        }

        // radix-16
        for i in 0..56 {
            output[2 * i] = bot_half(bytes[i]) as i8;
            output[2 * i + 1] = top_half(bytes[i]) as i8;
        }
        // re-center co-efficients to be between [-8, 8)
        for i in 0..112 {
            let carry = (output[i] + 8) >> 4;
            output[i] -= carry << 4;
            output[i + 1] += carry;
        }

        output
    }

    // XXX: Better if this method returns an array of 448 items
    /// Returns the bits of the scalar in little-endian order.
    pub fn bits(&self) -> [bool; 448] {
        let mut bits = [false; 448];
        let mut i = 0;
        // We have 56 limbs, each 8 bits
        // First we iterate each limb
        for limb in self.to_bytes().iter() {
            // Then we iterate each bit in the limb
            for j in 0..8 {
                bits[i] = limb & (1 << j) != 0;
                i += 1;
            }
        }

        // XXX :We are doing LSB first
        bits
    }

    /// Construct a `Scalar` from a little-endian byte representation.
    pub fn from_bytes(bytes: &[u8; 56]) -> Scalar {
        Self(U448::from_le_slice(bytes))
    }

    /// Convert this `Scalar` to a little-endian byte array.
    pub fn to_bytes(&self) -> [u8; 56] {
        let bytes = self.0.to_le_bytes();
        let output: [u8; 56] = core::array::from_fn(|i| bytes[i]);
        output
    }

    /// Invert this scalar
    pub fn invert(&self) -> Self {
        Self::conditional_select(
            &self.exp_vartime(&[
                0x2378c292ab5844f1,
                0x216cc2728dc58f55,
                0xc44edb49aed63690,
                0xffffffff7cca23e9,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0x3fffffffffffffff,
            ]),
            &Self::ZERO,
            self.is_zero(),
        )
    }

    /// Exponentiates `self` by `exp`, where `exp` is a little-endian order integer
    /// exponent.
    pub const fn exp_vartime(&self, exp: &[u64]) -> Self {
        let mut res = Self::ONE;

        let mut i = exp.len();
        while i > 0 {
            i -= 1;

            let mut j = 64;
            while j > 0 {
                j -= 1;
                res = res.square();

                if ((exp[i] >> j) & 1) == 1 {
                    res = res.multiply(self);
                }
            }
        }

        res
    }

    /// Return the square root of this scalar, if it is a quadratic residue.
    pub fn sqrt(&self) -> CtOption<Self> {
        let ss = self.pow([
            0x48de30a4aad6113d,
            0x085b309ca37163d5,
            0x7113b6d26bb58da4,
            0xffffffffdf3288fa,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x0fffffffffffffff,
        ]);
        CtOption::new(ss, ss.square().ct_eq(self))
    }

    /// Halves a Scalar modulo the prime
    pub const fn halve(&self) -> Self {
        Self(self.0.shr_vartime(1))
    }

    /// Attempt to construct a `Scalar` from a canonical byte representation.
    ///
    /// # Return
    ///
    /// - `Some(s)`, where `s` is the `Scalar` corresponding to `bytes`,
    ///   if `bytes` is a canonical byte representation;
    /// - `None` if `bytes` is not a canonical byte representation.
    pub fn from_canonical_bytes(bytes: &ScalarBytes) -> CtOption<Self> {
        // Check that the 10 high bits are not set
        let is_valid = is_zero(bytes[56]) | is_zero(bytes[55] >> 6);
        let bytes: [u8; 56] = core::array::from_fn(|i| bytes[i]);
        let candidate = Scalar::from_bytes(&bytes);

        // underflow means candidate < ORDER, thus canonical
        let (_, underflow) = candidate.0.sbb(&ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        CtOption::new(candidate, underflow & is_valid)
    }

    /// Serialize the scalar into 57 bytes, per RFC 8032.
    /// Byte 56 will always be zero.
    pub fn to_bytes_rfc_8032(&self) -> ScalarBytes {
        let mut bytes = ScalarBytes::default();
        bytes[..56].copy_from_slice(&self.to_bytes());
        bytes
    }

    /// Construct a `Scalar` by reducing a 912-bit little-endian integer
    /// modulo the group order ℓ.
    pub fn from_bytes_mod_order_wide(input: &WideScalarBytes) -> Scalar {
        // top multiplier = 2^896 mod ℓ
        const TOP_MULTIPLIER: U448 = U448::from_be_hex("3402a939f823b7292052bcb7e4d070af1a9cc14ba3c47c44ae17cf725ee4d8380d66de2388ea18597af32c4bc1b195d9e3539257049b9b60");
        let value = (
            U448::from_le_slice(&input[..56]),
            U448::from_le_slice(&input[56..112]),
        );
        let mut top = [0u8; 56];
        top[..2].copy_from_slice(&input[112..]);
        let upper = U448::from_le_slice(&top).mul_wide(&TOP_MULTIPLIER);

        let bottom = U448::const_rem_wide(value, &ORDER).0;
        let top = U448::const_rem_wide(upper, &ORDER).0;
        Self(bottom.add_mod(&top, &ORDER))
    }

    /// Construct a Scalar by reducing a 448-bit little-endian integer modulo the group order ℓ
    pub fn from_bytes_mod_order(input: &ScalarBytes) -> Scalar {
        let value = U448::from_le_slice(&input[..56]);
        Self(value.const_rem(&ORDER).0)
    }

    /// Return a `Scalar` chosen uniformly at random using a user-provided RNG.
    ///
    /// # Inputs
    ///
    /// * `rng`: any RNG which implements the `RngCore + CryptoRng` interface.
    ///
    /// # Returns
    ///
    /// A random scalar within ℤ/lℤ.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut scalar_bytes = WideScalarBytes::default();
        rng.fill_bytes(&mut scalar_bytes);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }

    /// Computes the hash to field routine according to Section 5
    /// <https://datatracker.ietf.org/doc/rfc9380/>
    /// and returns a scalar.
    ///
    /// # Errors
    /// See implementors of [`ExpandMsg`] for errors:
    /// - [`ExpandMsgXmd`]
    /// - [`ExpandMsgXof`]
    ///
    /// `len_in_bytes = <Self::Scalar as FromOkm>::Length`
    ///
    /// [`ExpandMsgXmd`]: crate::hash2curve::ExpandMsgXmd
    /// [`ExpandMsgXof`]: crate::hash2curve::ExpandMsgXof
    pub fn hash<X>(msg: &[u8], dst: &[u8]) -> Self
    where
        X: for<'a> ExpandMsg<'a>,
    {
        let mut random_bytes = GenericArray::<u8, U84>::default();
        let dst = [dst];
        let mut expander =
            X::expand_message(&[msg], &dst, random_bytes.len()).expect("invalid dst");
        expander.fill_bytes(&mut random_bytes);
        Self::from_okm(&random_bytes)
    }
}

fn is_zero(b: u8) -> Choice {
    let res = b as i8;
    Choice::from((((res | -res) >> 7) + 1) as u8)
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_basic_add() {
        let five = Scalar::from(5u8);
        let six = Scalar::from(6u8);

        assert_eq!(five + six, Scalar::from(11u8))
    }

    #[test]
    fn test_basic_sub() {
        let ten = Scalar::from(10u8);
        let five = Scalar::from(5u8);
        assert_eq!(ten - five, Scalar::from(5u8))
    }

    #[test]
    fn test_basic_mul() {
        let ten = Scalar::from(10u8);
        let five = Scalar::from(5u8);

        assert_eq!(ten * five, Scalar::from(50u8))
    }

    #[test]
    fn test_mul() {
        let a = Scalar(U448::from_be_hex(
            "1e63e8073b089f0747cf8cac2c3dc2732aae8688a8fa552ba8cb0ae8c0be082e74d657641d9ac30a087b8fb97f8ed27dc96a3c35ffb823a3"
        ));

        let b = Scalar(U448::from_be_hex(
            "16c5450acae1cb680a92de2d8e59b30824e8d4991adaa0e7bc343bcbd099595b188c6b1a1e30b38b17aa6d9be416b899686eb329d8bedc42"
        ));

        let exp = Scalar(U448::from_be_hex(
            "31e055c14ca389edfccd61b3203d424bb9036ff6f2d89c1e07bcd93174e9335f36a1492008a3a0e46abd26f5994c9c2b1f5b3197a18d010a"
        ));

        assert_eq!(a * b, exp)
    }
    #[test]
    fn test_basic_square() {
        let a = Scalar(U448::from_be_hex(
            "3162081604b3273b930392e5d2391f9d21cc3078f22c69514bb395e08dccc4866f08f3311370f8b83fa50692f640922b7e56a34bcf5fac3d",
        ));
        let expected_a_squared = Scalar(U448::from_be_hex(
            "1c1e32fc66b21c9c42d6e8e20487193cf6d49916421b290098f30de3713006cfe8ee9d21eeef7427f82a1fe036630c74b9acc2c2ede40f04",
        ));

        assert_eq!(a.square(), expected_a_squared)
    }

    #[test]
    fn test_sanity_check_index_mut() {
        let mut x = Scalar::ONE;
        x[0] = 2;
        assert_eq!(x, Scalar::from(2u8))
    }
    #[test]
    fn test_basic_halving() {
        let eight = Scalar::from(8u8);
        let four = Scalar::from(4u8);
        let two = Scalar::from(2u8);
        assert_eq!(eight.halve(), four);
        assert_eq!(four.halve(), two);
        assert_eq!(two.halve(), Scalar::ONE);
    }

    #[test]
    fn test_equals() {
        let a = Scalar::from(5u8);
        let b = Scalar::from(5u8);
        let c = Scalar::from(10u8);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_basic_inversion() {
        // Test inversion from 2 to 100
        for i in 1..=100u8 {
            let x = Scalar::from(i);
            let x_inv = x.invert();
            assert_eq!(x_inv * x, Scalar::ONE)
        }

        // Inversion of zero is zero
        let zero = Scalar::ZERO;
        let expected_zero = zero.invert();
        assert_eq!(expected_zero, zero)
    }
    #[test]
    fn test_serialise() {
        let scalar = Scalar(U448::from_be_hex(
            "0d79f6e375d3395ed9a6c4c3c49a1433fd7c58aa38363f74e9ab2c22a22347d79988f8e01e8a309f862a9f1052fcd042b9b1ed7115598f62",
        ));
        let got = Scalar::from_bytes(&scalar.to_bytes());
        assert_eq!(scalar, got)
    }
    #[test]
    fn test_debug() {
        let k = Scalar(U448::from_le_slice(&[
            200, 0, 0, 0, 210, 0, 0, 0, 250, 0, 0, 0, 145, 0, 0, 0, 130, 0, 0, 0, 180, 0, 0, 0,
            147, 0, 0, 0, 122, 0, 0, 0, 222, 0, 0, 0, 230, 0, 0, 0, 214, 0, 0, 0, 247, 0, 0, 0,
            203, 0, 0, 0, 32, 0, 0, 0,
        ]));
        let s = k;
        dbg!(&s.to_radix_16()[..]);
    }
    #[test]
    fn test_from_canonical_bytes() {
        // ff..ff should fail
        let mut bytes = ScalarBytes::clone_from_slice(&hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        bytes.reverse();
        let s = Scalar::from_canonical_bytes(&bytes);
        assert!(<Choice as Into<bool>>::into(s.is_none()));

        // n should fail
        let mut bytes = ScalarBytes::clone_from_slice(&hex!("003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"));
        bytes.reverse();
        let s = Scalar::from_canonical_bytes(&bytes);
        assert!(<Choice as Into<bool>>::into(s.is_none()));

        // n-1 should work
        let mut bytes = ScalarBytes::clone_from_slice(&hex!("003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2"));
        bytes.reverse();
        let s = Scalar::from_canonical_bytes(&bytes);
        match Option::<Scalar>::from(s) {
            Some(s) => assert_eq!(s, Scalar::ZERO - Scalar::ONE),
            None => panic!("should not return None"),
        };
    }

    #[test]
    fn test_from_bytes_mod_order_wide() {
        // n should become 0
        let mut bytes = WideScalarBytes::clone_from_slice(&hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"));
        bytes.reverse();
        let s = Scalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, Scalar::ZERO);

        // n-1 should stay the same
        let mut bytes = WideScalarBytes::clone_from_slice(&hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2"));
        bytes.reverse();
        let s = Scalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, Scalar::ZERO - Scalar::ONE);

        // n+1 should become 1
        let mut bytes = WideScalarBytes::clone_from_slice(&hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f4"));
        bytes.reverse();
        let s = Scalar::from_bytes_mod_order_wide(&bytes);
        assert_eq!(s, Scalar::ONE);

        // 2^912-1 should become 0x2939f823b7292052bcb7e4d070af1a9cc14ba3c47c44ae17cf72c985bb24b6c520e319fb37a63e29800f160787ad1d2e11883fa931e7de81
        let bytes = WideScalarBytes::clone_from_slice(&hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        let s = Scalar::from_bytes_mod_order_wide(&bytes);
        let mut bytes = ScalarBytes::clone_from_slice(&hex!("002939f823b7292052bcb7e4d070af1a9cc14ba3c47c44ae17cf72c985bb24b6c520e319fb37a63e29800f160787ad1d2e11883fa931e7de81"));
        bytes.reverse();
        let reduced = Scalar::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(s, reduced);
    }

    #[test]
    fn test_to_bytes_rfc8032() {
        // n-1
        let mut bytes: [u8; 57] = hex!("003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2");
        bytes.reverse();
        let x = Scalar::ZERO - Scalar::ONE;
        let candidate = x.to_bytes_rfc_8032();
        assert_eq!(&bytes[..], &candidate[..]);
    }

    #[cfg(all(any(feature = "alloc", feature = "std"), feature = "serde"))]
    #[test]
    fn serde() {
        let res = serde_json::to_string(&Scalar::TWO_INV);
        assert!(res.is_ok());
        let sj = res.unwrap();

        let res = serde_json::from_str::<Scalar>(&sj);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Scalar::TWO_INV);

        let res = serde_bare::to_vec(&Scalar::TWO_INV);
        assert!(res.is_ok());
        let sb = res.unwrap();
        assert_eq!(sb.len(), 57);

        let res = serde_bare::from_slice::<Scalar>(&sb);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Scalar::TWO_INV);
    }

    #[test]
    fn scalar_hash() {
        let msg = b"hello world";
        let dst = b"edwards448_XOF:SHAKE256_ELL2_RO_";
        let res =
            Scalar::hash::<elliptic_curve::hash2curve::ExpandMsgXof<sha3::Shake256>>(msg, dst);
        let expected = hex_literal::hex!("2d32a08f09b88275cc5f437e625696b18de718ed94559e17e4d64aafd143a8527705132178b5ce7395ea6214735387398a35913656b4951300");
        assert_eq!(res.to_bytes_rfc_8032(), expected.into());
    }
}
