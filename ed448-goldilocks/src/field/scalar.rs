use crate::*;

use core::cmp::Ordering;
use core::fmt::{Debug, Display, Formatter, Result as FmtResult};
use core::iter::{Product, Sum};
use core::marker::PhantomData;
use core::ops::{
    Add, AddAssign, Index, IndexMut, Mul, MulAssign, Neg, Shr, ShrAssign, Sub, SubAssign,
};
use elliptic_curve::{
    CurveArithmetic, PrimeField,
    array::{
        Array, ArraySize,
        typenum::{Prod, Unsigned},
    },
    bigint::{Limb, NonZero, U448, U896, Word, Zero},
    consts::U2,
    ff::{Field, helpers},
    ops::{Invert, Reduce, ReduceNonZero},
    scalar::{FromUintUnchecked, IsHigh},
};
use rand_core::{CryptoRng, RngCore, TryRngCore};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption};

#[cfg(feature = "bits")]
use elliptic_curve::ff::{FieldBits, PrimeFieldBits};

/// Shared scalar for [`Ed448`] and [`Decaf448`].
/// Use [`EdwardsScalar`] and [`DecafScalar`] directly.
///
/// This is the scalar field
/// size = 4q = 2^446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
/// We can therefore use 14 saturated 32-bit limbs
pub struct Scalar<C: CurveWithScalar> {
    pub(crate) scalar: U448,
    curve: PhantomData<C>,
}

/// The number of bytes needed to represent the scalar field
pub type ScalarBytes<C> = Array<u8, <C as CurveWithScalar>::ReprSize>;
/// The number of bytes needed to represent the safely create a scalar from a random bytes
pub type WideScalarBytes<C> = Array<u8, Prod<<C as CurveWithScalar>::ReprSize, U2>>;

pub trait CurveWithScalar: 'static + CurveArithmetic + Send + Sync {
    type ReprSize: ArraySize<ArrayType<u8>: Copy> + Mul<U2, Output: ArraySize<ArrayType<u8>: Copy>>;

    fn from_bytes_mod_order_wide(input: &WideScalarBytes<Self>) -> Scalar<Self>;

    fn from_canonical_bytes(bytes: &ScalarBytes<Self>) -> CtOption<Scalar<Self>>;

    fn to_repr(scalar: &Scalar<Self>) -> ScalarBytes<Self>;
}

/// The order of the scalar field
pub const ORDER: U448 = U448::from_be_hex(
    "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
);
pub const NZ_ORDER: NonZero<U448> = NonZero::<U448>::new_unwrap(ORDER);
const ORDER_MINUS_ONE: U448 = ORDER.wrapping_sub(&U448::ONE);
const HALF_ORDER: U448 = ORDER.shr_vartime(1);
/// The wide order of the scalar field
pub const WIDE_ORDER: U896 = U896::from_be_hex(
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
);
const WIDE_ORDER_MINUS_ONE: U896 = WIDE_ORDER.wrapping_sub(&U896::ONE);

/// The modulus of the scalar field as a sequence of 14 32-bit limbs
pub const MODULUS_LIMBS: [u32; 14] = [
    0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272, 0xaed63690, 0xc44edb49, 0x7cca23e9, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff,
];

impl<C: CurveWithScalar> Clone for Scalar<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: CurveWithScalar> Copy for Scalar<C> {}

impl<C: CurveWithScalar> Debug for Scalar<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_tuple("Scalar").field(&self.scalar).finish()
    }
}

impl<C: CurveWithScalar> Default for Scalar<C> {
    fn default() -> Self {
        Self::new(U448::default())
    }
}

impl<C: CurveWithScalar> Display for Scalar<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let bytes = self.to_repr();
        for b in &bytes {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl<C: CurveWithScalar> ConstantTimeEq for Scalar<C> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl<C: CurveWithScalar> ConditionallySelectable for Scalar<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::new(U448::conditional_select(&a.scalar, &b.scalar, choice))
    }
}

impl<C: CurveWithScalar> PartialEq for Scalar<C> {
    fn eq(&self, other: &Scalar<C>) -> bool {
        self.ct_eq(other).into()
    }
}

impl<C: CurveWithScalar> Eq for Scalar<C> {}

impl<C: CurveWithScalar> PartialOrd for Scalar<C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<C: CurveWithScalar> Ord for Scalar<C> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.scalar.cmp(&other.scalar)
    }
}

impl<C: CurveWithScalar> From<u8> for Scalar<C> {
    fn from(a: u8) -> Self {
        Scalar::new(U448::from_u8(a))
    }
}

impl<C: CurveWithScalar> From<u16> for Scalar<C> {
    fn from(a: u16) -> Self {
        Scalar::new(U448::from_u16(a))
    }
}

impl<C: CurveWithScalar> From<u32> for Scalar<C> {
    fn from(a: u32) -> Scalar<C> {
        Scalar::new(U448::from_u32(a))
    }
}

impl<C: CurveWithScalar> From<u64> for Scalar<C> {
    fn from(a: u64) -> Self {
        Scalar::new(U448::from_u64(a))
    }
}

impl<C: CurveWithScalar> From<u128> for Scalar<C> {
    fn from(a: u128) -> Self {
        Scalar::new(U448::from_u128(a))
    }
}

impl<C: CurveWithScalar> Index<usize> for Scalar<C> {
    type Output = Word;

    fn index(&self, index: usize) -> &Self::Output {
        &self.scalar.as_words()[index]
    }
}

impl<C: CurveWithScalar> IndexMut<usize> for Scalar<C> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.scalar.as_mut_words()[index]
    }
}

// Trait implementations
impl<C: CurveWithScalar> Add<&Scalar<C>> for &Scalar<C> {
    type Output = Scalar<C>;

    fn add(self, rhs: &Scalar<C>) -> Self::Output {
        self.addition(rhs)
    }
}

define_add_variants!(GENERIC = C: CurveWithScalar, LHS = Scalar<C>, RHS = Scalar<C>, Output = Scalar<C>);

impl<C: CurveWithScalar> AddAssign for Scalar<C> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl<C: CurveWithScalar> AddAssign<&Scalar<C>> for Scalar<C> {
    fn add_assign(&mut self, rhs: &Scalar<C>) {
        *self = *self + rhs
    }
}

impl<C: CurveWithScalar> Mul<&Scalar<C>> for &Scalar<C> {
    type Output = Scalar<C>;

    fn mul(self, rhs: &Scalar<C>) -> Self::Output {
        self.multiply(rhs)
    }
}

define_mul_variants!(GENERIC = C: CurveWithScalar, LHS = Scalar<C>, RHS = Scalar<C>, Output = Scalar<C>);

impl<C: CurveWithScalar> MulAssign for Scalar<C> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs
    }
}

impl<C: CurveWithScalar> MulAssign<&Scalar<C>> for Scalar<C> {
    fn mul_assign(&mut self, rhs: &Scalar<C>) {
        *self = *self * rhs
    }
}

impl<C: CurveWithScalar> Sub<&Scalar<C>> for &Scalar<C> {
    type Output = Scalar<C>;

    fn sub(self, rhs: &Scalar<C>) -> Self::Output {
        self.subtract(rhs)
    }
}

define_sub_variants!(GENERIC = C: CurveWithScalar, LHS = Scalar<C>, RHS = Scalar<C>, Output = Scalar<C>);

impl<C: CurveWithScalar> SubAssign for Scalar<C> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs
    }
}

impl<C: CurveWithScalar> SubAssign<&Scalar<C>> for Scalar<C> {
    fn sub_assign(&mut self, rhs: &Scalar<C>) {
        *self = *self - rhs
    }
}

impl<C: CurveWithScalar> Neg for Scalar<C> {
    type Output = Scalar<C>;

    fn neg(self) -> Self::Output {
        -&self
    }
}

impl<C: CurveWithScalar> Neg for &Scalar<C> {
    type Output = Scalar<C>;

    fn neg(self) -> Self::Output {
        Scalar::ZERO - self
    }
}

impl<C: CurveWithScalar> Sum for Scalar<C> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut acc = Scalar::ZERO;
        for s in iter {
            acc += s;
        }
        acc
    }
}

impl<'a, C: CurveWithScalar> Sum<&'a Scalar<C>> for Scalar<C> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let mut acc = Scalar::ZERO;
        for s in iter {
            acc += s;
        }
        acc
    }
}

impl<C: CurveWithScalar> Product for Scalar<C> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut acc = Scalar::ONE;
        for s in iter {
            acc *= s;
        }
        acc
    }
}

impl<'a, C: CurveWithScalar> Product<&'a Scalar<C>> for Scalar<C> {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let mut acc = Scalar::ONE;
        for s in iter {
            acc *= s;
        }
        acc
    }
}

impl<C: CurveWithScalar> Field for Scalar<C> {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    fn try_from_rng<R: TryRngCore + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut seed = WideScalarBytes::<C>::default();
        rng.try_fill_bytes(&mut seed)?;
        Ok(C::from_bytes_mod_order_wide(&seed))
    }

    fn square(&self) -> Self {
        self.square()
    }

    fn double(&self) -> Self {
        self.double()
    }

    fn invert(&self) -> CtOption<Self> {
        CtOption::new(self.invert(), !self.ct_eq(&Self::ZERO))
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        helpers::sqrt_ratio_generic(num, div)
    }
}

impl<C: CurveWithScalar> PrimeField for Scalar<C> {
    type Repr = ScalarBytes<C>;

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        Self::from_canonical_bytes(&repr)
    }
    fn to_repr(&self) -> Self::Repr {
        C::to_repr(self)
    }
    fn is_odd(&self) -> Choice {
        Choice::from((self.scalar.to_words()[0] & 1) as u8)
    }
    const MODULUS: &'static str = "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3";
    const NUM_BITS: u32 = 448;
    const CAPACITY: u32 = Self::NUM_BITS - 1;
    const TWO_INV: Self = Self::new(U448::from_be_hex(
        "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffbe6511f4e2276da4d76b1b4810b6613946e2c7aa91bc614955ac227a",
    ));
    const MULTIPLICATIVE_GENERATOR: Self = Self::new(U448::from_u8(7));
    const S: u32 = 1;

    const ROOT_OF_UNITY: Self = Self::new(U448::from_be_hex(
        "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2",
    ));

    const ROOT_OF_UNITY_INV: Self = Self::new(U448::from_be_hex(
        "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f2",
    ));

    const DELTA: Self = Self::new(U448::from_u8(49));
}

#[cfg(feature = "alloc")]
impl<C: CurveWithScalar> From<Scalar<C>> for Vec<u8> {
    fn from(scalar: Scalar<C>) -> Vec<u8> {
        Self::from(&scalar)
    }
}

#[cfg(feature = "alloc")]
impl<C: CurveWithScalar> From<&Scalar<C>> for Vec<u8> {
    fn from(scalar: &Scalar<C>) -> Vec<u8> {
        C::to_repr(scalar).to_vec()
    }
}

impl<C: CurveWithScalar> From<Scalar<C>> for ScalarBytes<C> {
    fn from(scalar: Scalar<C>) -> ScalarBytes<C> {
        Self::from(&scalar)
    }
}

impl<C: CurveWithScalar> From<&Scalar<C>> for ScalarBytes<C> {
    fn from(scalar: &Scalar<C>) -> ScalarBytes<C> {
        C::to_repr(scalar)
    }
}

#[cfg(feature = "alloc")]
impl<C: CurveWithScalar> TryFrom<Vec<u8>> for Scalar<C> {
    type Error = &'static str;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&bytes[..])
    }
}

#[cfg(feature = "alloc")]
impl<C: CurveWithScalar> TryFrom<&Vec<u8>> for Scalar<C> {
    type Error = &'static str;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&bytes[..])
    }
}

impl<C: CurveWithScalar> TryFrom<&[u8]> for Scalar<C> {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != C::ReprSize::USIZE {
            return Err("invalid byte length");
        }
        let scalar_bytes = ScalarBytes::<C>::try_from(bytes).expect("invalid scalar bytes");
        Option::<Scalar<C>>::from(Scalar::from_canonical_bytes(&scalar_bytes))
            .ok_or("scalar was not canonically encoded")
    }
}

#[cfg(feature = "alloc")]
impl<C: CurveWithScalar> TryFrom<Box<[u8]>> for Scalar<C> {
    type Error = &'static str;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

#[cfg(feature = "serde")]
impl<C: CurveWithScalar> serdect::serde::Serialize for Scalar<C> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.to_bytes(), s)
    }
}

#[cfg(feature = "serde")]
impl<'de, C: CurveWithScalar> serdect::serde::Deserialize<'de> for Scalar<C> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let mut buffer = ScalarBytes::<C>::default();
        serdect::array::deserialize_hex_or_bin(&mut buffer[..56], d)?;
        Option::from(Self::from_canonical_bytes(&buffer)).ok_or(serdect::serde::de::Error::custom(
            "scalar was not canonically encoded",
        ))
    }
}

impl<C: CurveWithScalar> elliptic_curve::zeroize::DefaultIsZeroes for Scalar<C> {}

impl<C: CurveWithScalar> core::fmt::LowerHex for Scalar<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let tmp = C::to_repr(self);
        for &b in tmp.iter() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl<C: CurveWithScalar> core::fmt::UpperHex for Scalar<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let tmp = C::to_repr(self);
        for &b in tmp.iter() {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl<C: CurveWithScalar> Reduce<U448> for Scalar<C> {
    type Bytes = ScalarBytes<C>;

    fn reduce(bytes: U448) -> Self {
        let (r, underflow) = bytes.borrowing_sub(&ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::new(U448::conditional_select(&bytes, &r, !underflow))
    }

    fn reduce_bytes(bytes: &Self::Bytes) -> Self {
        Self::reduce(U448::from_le_slice(bytes))
    }
}

impl<C: CurveWithScalar> Reduce<U896> for Scalar<C> {
    type Bytes = WideScalarBytes<C>;

    fn reduce(bytes: U896) -> Self {
        let (r, underflow) = bytes.borrowing_sub(&WIDE_ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::new(U896::conditional_select(&bytes, &r, !underflow).split().1)
    }

    fn reduce_bytes(bytes: &Self::Bytes) -> Self {
        C::from_bytes_mod_order_wide(bytes)
    }
}

impl<C: CurveWithScalar> ReduceNonZero<U448> for Scalar<C> {
    fn reduce_nonzero(bytes: U448) -> Self {
        let (r, underflow) = bytes.borrowing_sub(&ORDER_MINUS_ONE, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::new(U448::conditional_select(&bytes, &r, !underflow).wrapping_add(&U448::ONE))
    }

    fn reduce_nonzero_bytes(bytes: &Self::Bytes) -> Self {
        Self::reduce_nonzero(U448::from_le_slice(bytes))
    }
}

impl<C: CurveWithScalar> ReduceNonZero<U896> for Scalar<C> {
    fn reduce_nonzero(bytes: U896) -> Self {
        let (r, underflow) = bytes.borrowing_sub(&WIDE_ORDER_MINUS_ONE, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);

        Self::new(
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

#[cfg(feature = "bits")]
impl<C: CurveWithScalar> PrimeFieldBits for Scalar<C> {
    type ReprBits = [Word; U448::LIMBS];

    fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
        self.scalar.to_words().into()
    }

    fn char_le_bits() -> FieldBits<Self::ReprBits> {
        ORDER.to_words().into()
    }
}

impl<C: CurveWithScalar> From<U448> for Scalar<C> {
    fn from(uint: U448) -> Self {
        <Self as Reduce<U448>>::reduce(uint)
    }
}

impl<C: CurveWithScalar> From<&U448> for Scalar<C> {
    fn from(uint: &U448) -> Self {
        Self::from(*uint)
    }
}

impl<C: CurveWithScalar> From<Scalar<C>> for U448 {
    fn from(scalar: Scalar<C>) -> Self {
        scalar.scalar
    }
}

impl<C: CurveWithScalar> From<&Scalar<C>> for U448 {
    fn from(scalar: &Scalar<C>) -> Self {
        Self::from(*scalar)
    }
}

impl<C: CurveWithScalar> FromUintUnchecked for Scalar<C> {
    type Uint = U448;

    fn from_uint_unchecked(uint: U448) -> Self {
        Self::new(uint)
    }
}

impl<C: CurveWithScalar> Invert for Scalar<C> {
    type Output = CtOption<Self>;

    fn invert(&self) -> CtOption<Self> {
        CtOption::new(self.invert(), !self.ct_eq(&Self::ZERO))
    }
}

impl<C: CurveWithScalar> IsHigh for Scalar<C> {
    fn is_high(&self) -> Choice {
        self.scalar.ct_gt(&HALF_ORDER)
    }
}

impl<C: CurveWithScalar> AsRef<Scalar<C>> for Scalar<C> {
    fn as_ref(&self) -> &Scalar<C> {
        self
    }
}

impl<C: CurveWithScalar> Shr<usize> for Scalar<C> {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        let mut cp = self;
        cp.shr_assign(rhs);
        cp
    }
}

impl<C: CurveWithScalar> Shr<usize> for &Scalar<C> {
    type Output = Scalar<C>;

    fn shr(self, rhs: usize) -> Self::Output {
        let mut cp = *self;
        cp.shr_assign(rhs);
        cp
    }
}

impl<C: CurveWithScalar> ShrAssign<usize> for Scalar<C> {
    fn shr_assign(&mut self, shift: usize) {
        self.scalar >>= shift;
    }
}

impl<C: CurveWithScalar> Scalar<C> {
    /// The multiplicative identity element
    pub const ONE: Scalar<C> = Scalar::new(U448::ONE);
    /// Twice the multiplicative identity element
    pub const TWO: Scalar<C> = Scalar::new(U448::from_u8(2));
    /// The additive identity element
    pub const ZERO: Scalar<C> = Scalar::new(U448::ZERO);

    pub(crate) const fn new(scalar: U448) -> Self {
        Self {
            scalar,
            curve: PhantomData,
        }
    }

    /// Compute `self` + `rhs` mod ℓ
    pub const fn addition(&self, rhs: &Self) -> Self {
        Self::new(self.scalar.add_mod(&rhs.scalar, &ORDER))
    }

    /// Compute `self` + `self` mod ℓ
    pub const fn double(&self) -> Self {
        Self::new(self.scalar.double_mod(&ORDER))
    }

    /// Compute `self` - `rhs` mod ℓ
    pub const fn subtract(&self, rhs: &Self) -> Self {
        Self::new(self.scalar.sub_mod(&rhs.scalar, &ORDER))
    }

    /// Compute `self` * `rhs` mod ℓ
    pub const fn multiply(&self, rhs: &Self) -> Self {
        let wide_value = self.scalar.widening_mul(&rhs.scalar);
        Self::new(U448::rem_wide_vartime(wide_value, &NZ_ORDER))
    }

    /// Square this scalar
    pub const fn square(&self) -> Self {
        let value = self.scalar.square_wide();
        Self::new(U448::rem_wide_vartime(value, &NZ_ORDER))
    }

    /// Is this scalar equal to zero?
    pub fn is_zero(&self) -> Choice {
        self.scalar.is_zero()
    }

    /// Divides a scalar by four without reducing mod p
    /// This is used in the 2-isogeny when mapping points from Ed448-Goldilocks
    /// to Twisted-Goldilocks
    pub(crate) fn div_by_four(&mut self) {
        self.scalar >>= 2;
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

    /// Convert this `Scalar` to a little-endian byte array.
    pub fn to_bytes(&self) -> [u8; 56] {
        self.scalar.to_le_byte_array().0
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
        Self::new(self.scalar.shr_vartime(1))
    }

    /// Attempt to construct a `Scalar` from a canonical byte representation.
    ///
    /// # Return
    ///
    /// - `Some(s)`, where `s` is the `Scalar` corresponding to `bytes`,
    ///   if `bytes` is a canonical byte representation;
    /// - `None` if `bytes` is not a canonical byte representation.
    pub fn from_canonical_bytes(bytes: &ScalarBytes<C>) -> CtOption<Self> {
        C::from_canonical_bytes(bytes)
    }

    /// Construct a Scalar by reducing a 448-bit little-endian integer modulo the group order ℓ
    pub fn from_bytes_mod_order(input: &ScalarBytes<C>) -> Scalar<C> {
        let value = U448::from_le_slice(&input[..56]);
        Self::new(value.rem_vartime(&NZ_ORDER))
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
        let mut scalar_bytes = WideScalarBytes::<C>::default();
        rng.fill_bytes(&mut scalar_bytes);
        C::from_bytes_mod_order_wide(&scalar_bytes)
    }
}
