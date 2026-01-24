//! Field arithmetic modulo p = 2^{521} − 1
//!
//! Arithmetic implementations have been synthesized using fiat-crypto.
//!
//! # License
//!
//! Copyright (c) 2015-2020 the fiat-crypto authors
//!
//! fiat-crypto is distributed under the terms of the MIT License, the
//! Apache License (Version 2.0), and the BSD 1-Clause License;
//! users may pick which license to apply.

#[cfg_attr(target_pointer_width = "32", path = "field/p521_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field/p521_64.rs")]
#[allow(clippy::needless_lifetimes, clippy::unnecessary_cast)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
#[rustfmt::skip]
mod field_impl;
mod loose;

pub(crate) use self::loose::LooseFieldElement;

use self::field_impl::*;
use crate::{FieldBytes, NistP521, Uint};
use core::{
    cmp::Ordering,
    fmt::{self, Debug},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::{
    Error, FieldBytesEncoding, Generate,
    array::Array,
    bigint::{Word, modular::Retrieve},
    ff::{self, Field, PrimeField},
    ops::Invert,
    rand_core::TryRng,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess, CtOption},
    zeroize::DefaultIsZeroes,
};
use primefield::bigint::{self, Limb, Odd};

#[cfg(target_pointer_width = "32")]
const MODULUS_HEX: &str = "000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
#[cfg(target_pointer_width = "64")]
const MODULUS_HEX: &str = "00000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Field modulus: p = 2^{521} − 1
pub(crate) const MODULUS: Uint = Uint::from_be_hex(MODULUS_HEX);

/// Element of the secp521r1 base field used for curve coordinates.
#[derive(Clone, Copy)]
pub struct FieldElement(pub(crate) fiat_p521_tight_field_element);

impl FieldElement {
    /// Zero element.
    pub const ZERO: Self = Self::from_u64(0);

    /// Multiplicative identity.
    pub const ONE: Self = Self::from_u64(1);

    #[cfg(target_pointer_width = "32")]
    const LIMBS: usize = 19;
    #[cfg(target_pointer_width = "64")]
    const LIMBS: usize = 9;

    /// Create a [`FieldElement`] from a canonical big-endian representation.
    pub fn from_bytes(repr: &FieldBytes) -> CtOption<Self> {
        let uint = <Uint as FieldBytesEncoding<NistP521>>::decode_field_bytes(repr);
        Self::from_uint(uint)
    }

    /// Decode [`FieldElement`] from a big endian byte slice.
    pub fn from_slice(slice: &[u8]) -> elliptic_curve::Result<Self> {
        let field_bytes = FieldBytes::try_from(slice).map_err(|_| Error)?;
        Self::from_bytes(&field_bytes).into_option().ok_or(Error)
    }

    /// Decode [`FieldElement`] from [`Uint`].
    pub fn from_uint(uint: Uint) -> CtOption<Self> {
        let is_some = uint.ct_lt(&MODULUS);
        CtOption::new(Self::from_uint_unchecked(uint), is_some)
    }

    /// Parse a [`FieldElement`] from big endian hex-encoded bytes.
    ///
    /// This method is primarily intended for defining internal constants.
    ///
    /// # Panics
    /// - if the input in hex is not the correct length
    /// - if the given value when decoded from hex overflows the modulus
    pub(crate) const fn from_hex(hex: &str) -> Self {
        assert!(
            hex.len() == 521usize.div_ceil(8) * 2,
            "hex is the wrong length (expected 132 hex chars)"
        );

        // Build a hex string of the expected size, regardless of the size of `Uint`
        let mut hex_bytes = [b'0'; { Uint::BITS as usize / 4 }];

        let offset = hex_bytes.len() - hex.len();
        let mut i = 0;
        while i < hex.len() {
            hex_bytes[i + offset] = hex.as_bytes()[i];
            i += 1;
        }

        let uint = match core::str::from_utf8(&hex_bytes) {
            Ok(padded_hex) => Uint::from_be_hex(padded_hex),
            Err(_) => panic!("invalid hex string"),
        };

        assert!(matches!(uint.cmp_vartime(&MODULUS), Ordering::Less));
        Self::from_uint_unchecked(uint)
    }

    /// Convert a `u64` into a [`FieldElement`].
    pub const fn from_u64(w: u64) -> Self {
        Self::from_uint_unchecked(Uint::from_u64(w))
    }

    /// Decode [`FieldElement`] from [`Uint`].
    ///
    /// Does *not* perform a check that the field element does not overflow the order.
    ///
    /// Used incorrectly this can lead to invalid results!
    pub(crate) const fn from_uint_unchecked(w: Uint) -> Self {
        // Converts the saturated representation used by `Uint` into a 66-byte array with a
        // little-endian byte ordering.
        // TODO(tarcieri): use `FieldBytesEncoding::encode_field_bytes` when `const impl` is stable
        let le_bytes_wide = w.to_le_bytes();

        let mut le_bytes = [0u8; 66];
        let mut i = 0;

        // Extract the first 66-bytes of the 72-byte (576-bit) little endian serialized value
        while i < le_bytes.len() {
            le_bytes[i] = le_bytes_wide.as_slice()[i];
            i += 1;
        }

        // Decode the little endian serialization into the unsaturated big integer form used by
        // the fiat-crypto synthesized code.
        let mut out = fiat_p521_tight_field_element([0; Self::LIMBS]);
        fiat_p521_from_bytes(&mut out, &le_bytes);
        Self(out)
    }

    /// Returns the big-endian encoding of this [`FieldElement`].
    pub const fn to_bytes(self) -> FieldBytes {
        const BYTES: usize = 66;

        let mut ret = [0u8; BYTES];
        fiat_p521_to_bytes(&mut ret, &self.0);

        // TODO(tarcieri): use `reverse` when const-stable (MSRV 1.90)
        // ret.reverse();
        let mut i = 0;
        while i < (BYTES / 2) {
            let j = BYTES - i - 1;
            let tmp = ret[i];
            ret[i] = ret[j];
            ret[j] = tmp;
            i += 1;
        }

        Array(ret)
    }

    /// Determine if this [`FieldElement`] is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        Choice::from(self.0[0] as u8 & 1)
    }

    /// Determine if this [`FieldElement`] is even in the SEC1 sense: `self mod 2 == 0`.
    ///
    /// # Returns
    ///
    /// If even, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_even(&self) -> Choice {
        !self.is_odd()
    }

    /// Determine if this [`FieldElement`] is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Add elements.
    #[inline]
    pub const fn add_loose(&self, rhs: &Self) -> LooseFieldElement {
        let mut out = fiat_p521_loose_field_element([0; Self::LIMBS]);
        fiat_p521_add(&mut out, &self.0, &rhs.0);
        LooseFieldElement(out)
    }

    /// Double element (add it to itself).
    #[inline]
    #[must_use]
    pub const fn double_loose(&self) -> LooseFieldElement {
        self.add_loose(self)
    }

    /// Subtract elements, returning a loose field element.
    #[inline]
    pub const fn sub_loose(&self, rhs: &Self) -> LooseFieldElement {
        let mut out = fiat_p521_loose_field_element([0; Self::LIMBS]);
        fiat_p521_sub(&mut out, &self.0, &rhs.0);
        LooseFieldElement(out)
    }

    /// Negate element, returning a loose field element.
    #[inline]
    pub const fn neg_loose(&self) -> LooseFieldElement {
        let mut out = fiat_p521_loose_field_element([0; Self::LIMBS]);
        fiat_p521_opp(&mut out, &self.0);
        LooseFieldElement(out)
    }

    /// Add two field elements.
    #[inline]
    pub const fn add(&self, rhs: &Self) -> Self {
        let mut out = fiat_p521_tight_field_element([0; Self::LIMBS]);
        fiat_p521_carry_add(&mut out, &self.0, &rhs.0);
        Self(out)
    }

    /// Subtract field elements.
    #[inline]
    pub const fn sub(&self, rhs: &Self) -> Self {
        let mut out = fiat_p521_tight_field_element([0; Self::LIMBS]);
        fiat_p521_carry_sub(&mut out, &self.0, &rhs.0);
        Self(out)
    }

    /// Negate element.
    #[inline]
    pub const fn neg(&self) -> Self {
        let mut out = fiat_p521_tight_field_element([0; Self::LIMBS]);
        fiat_p521_carry_opp(&mut out, &self.0);
        Self(out)
    }

    /// Double element (add it to itself).
    #[inline]
    #[must_use]
    pub const fn double(&self) -> Self {
        self.add(self)
    }

    /// Multiply elements.
    #[inline]
    pub const fn multiply(&self, rhs: &Self) -> Self {
        self.relax().multiply(&rhs.relax())
    }

    /// Square element.
    #[inline]
    pub const fn square(&self) -> Self {
        self.relax().square()
    }

    /// Returns self^(2^n) mod p
    const fn sqn(&self, n: usize) -> Self {
        self.sqn_vartime(n)
    }

    /// Returns `self^exp`, where `exp` is a little-endian integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent `exp`.**
    ///
    /// If the exponent is fixed, this operation is constant time.
    pub const fn pow_vartime<const RHS_LIMBS: usize>(&self, exp: &bigint::Uint<RHS_LIMBS>) -> Self {
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

    /// Compute [`FieldElement`] inversion: `1 / self`.
    pub fn invert(&self) -> CtOption<Self> {
        self.to_uint()
            .invert_odd_mod(const { &Odd::from_be_hex(MODULUS_HEX) })
            .map(Self::from_uint_unchecked)
            .into()
    }

    /// Compute [`FieldElement`] inversion: `1 / self` in variable-time.
    pub fn invert_vartime(&self) -> CtOption<Self> {
        self.to_uint()
            .invert_odd_mod_vartime(const { &Odd::from_be_hex(MODULUS_HEX) })
            .map(Self::from_uint_unchecked)
            .into()
    }

    /// Returns the multiplicative inverse of self.
    ///
    /// # Panics
    /// Will panic in the event `self` is zero
    const fn invert_unwrap(&self) -> Self {
        Self::from_uint_unchecked(
            self.to_uint()
                .invert_odd_mod(const { &Odd::from_be_hex(MODULUS_HEX) })
                .expect_copied("input should be non-zero"),
        )
    }

    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    ///
    /// # Implementation details
    /// If _x_ has a sqrt, then due to Euler's criterion this implies x<sup>(p - 1)/2</sup> = 1.
    /// 1. x<sup>(p + 1)/2</sup> = x.
    /// 2. There's a special property due to _p ≡ 3 (mod 4)_ which implies _(p + 1)/4_ is an integer.
    /// 3. We can rewrite `1.` as x<sup>((p+1)/4)<sup>2</sup></sup>
    /// 4. x<sup>(p+1)/4</sup> is the square root.
    /// 5. This is simplified as (2<sup>251</sup> - 1 + 1) /4 = 2<sup>519</sup>
    /// 6. Hence, x<sup>2<sup>519</sup></sup> is the square root iff _result.square() == self_
    pub fn sqrt(&self) -> CtOption<Self> {
        let sqrt = self.sqn(519);
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }

    /// Relax a tight field element into a loose one.
    #[inline]
    pub const fn relax(&self) -> LooseFieldElement {
        let mut out = fiat_p521_loose_field_element([0; Self::LIMBS]);
        fiat_p521_relax(&mut out, &self.0);
        LooseFieldElement(out)
    }

    /// Raise this field element into a canonical integer representative.
    #[inline]
    pub(crate) const fn to_uint(self) -> Uint {
        let field_bytes = self.to_bytes();
        let mut uint_bytes = [0u8; Uint::LIMBS * Limb::BYTES];

        let offset = uint_bytes.len() - field_bytes.0.len();
        let mut i = 0;
        while i < field_bytes.0.len() {
            uint_bytes[i + offset] = field_bytes.0[i];
            i += 1
        }

        Uint::from_be_slice(&uint_bytes)
    }
}

impl AsRef<fiat_p521_tight_field_element> for FieldElement {
    fn as_ref(&self) -> &fiat_p521_tight_field_element {
        &self.0
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Debug for FieldElement {
    /// Formatting machinery for [`FieldElement`]
    ///
    /// # Why
    /// ```ignore
    /// let fe1 = FieldElement([9, 0, 0, 0, 0, 0, 0, 0, 0]);
    /// let fe2 = FieldElement([
    ///     8,
    ///     0,
    ///     288230376151711744,
    ///     288230376151711743,
    ///     288230376151711743,
    ///     288230376151711743,
    ///     288230376151711743,
    ///     288230376151711743,
    ///     144115188075855871,
    /// ]);
    /// ```
    ///
    /// For the above example, deriving [`core::fmt::Debug`] will result in returning 2 different
    /// strings, which are in reality the same due to p521's unsaturated math, instead print the
    /// output as a hex string in big-endian.
    ///
    /// This makes debugging easier.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        let formatter = base16ct::HexDisplay(&bytes);
        f.debug_tuple("FieldElement")
            .field(&format_args!("0x{formatter:X}"))
            .finish()
    }
}

impl Eq for FieldElement {}
impl PartialEq for FieldElement {
    fn eq(&self, rhs: &Self) -> bool {
        self.ct_eq(rhs).into()
    }
}

impl From<u32> for FieldElement {
    fn from(n: u32) -> FieldElement {
        Self::from_uint_unchecked(Uint::from(n))
    }
}

impl From<u64> for FieldElement {
    fn from(n: u64) -> FieldElement {
        Self::from_uint_unchecked(Uint::from(n))
    }
}

impl From<u128> for FieldElement {
    fn from(n: u128) -> FieldElement {
        Self::from_uint_unchecked(Uint::from(n))
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let out = <[Word; Self::LIMBS]>::conditional_select(&a.0.0, &b.0.0, choice);
        Self(fiat_p521_tight_field_element(out))
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        let a = self.to_bytes();
        let b = other.to_bytes();
        a.ct_eq(&b)
    }
}

impl DefaultIsZeroes for FieldElement {}

impl Field for FieldElement {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    fn try_from_rng<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        // NOTE: can't use ScalarValue::random due to CryptoRng bound
        let mut bytes = <FieldBytes>::default();

        loop {
            rng.try_fill_bytes(&mut bytes)?;
            if let Some(fe) = Self::from_bytes(&bytes).into() {
                return Ok(fe);
            }
        }
    }

    fn is_zero(&self) -> Choice {
        Self::ZERO.ct_eq(self)
    }

    fn square(&self) -> Self {
        self.square()
    }

    fn double(&self) -> Self {
        self.double()
    }

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }

    fn sqrt(&self) -> CtOption<Self> {
        self.sqrt()
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        ff::helpers::sqrt_ratio_generic(num, div)
    }
}

impl Generate for FieldElement {
    fn try_generate_from_rng<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        Self::try_from_rng(rng)
    }
}

impl PrimeField for FieldElement {
    type Repr = FieldBytes;

    const MODULUS: &'static str = MODULUS_HEX;
    const NUM_BITS: u32 = 521;
    const CAPACITY: u32 = 520;
    const TWO_INV: Self = Self::from_u64(2).invert_unwrap();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(3);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self = Self::from_hex(
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    );
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unwrap();
    const DELTA: Self = Self::from_u64(9);

    #[inline]
    fn from_repr(bytes: FieldBytes) -> CtOption<Self> {
        Self::from_bytes(&bytes)
    }

    #[inline]
    fn to_repr(&self) -> FieldBytes {
        self.to_bytes()
    }

    #[inline]
    fn is_odd(&self) -> Choice {
        self.is_odd()
    }
}

//
// `core::ops` impls
//

impl Add for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn add(self, rhs: FieldElement) -> FieldElement {
        Self::add(&self, &rhs)
    }
}

impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn add(self, rhs: &FieldElement) -> FieldElement {
        Self::add(&self, rhs)
    }
}

impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    #[inline]
    fn add(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::add(self, rhs)
    }
}

impl AddAssign<FieldElement> for FieldElement {
    #[inline]
    fn add_assign(&mut self, other: FieldElement) {
        *self = *self + other;
    }
}

impl AddAssign<&FieldElement> for FieldElement {
    #[inline]
    fn add_assign(&mut self, other: &FieldElement) {
        *self = *self + other;
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn sub(self, rhs: FieldElement) -> FieldElement {
        Self::sub(&self, &rhs)
    }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn sub(self, rhs: &FieldElement) -> FieldElement {
        Self::sub(&self, rhs)
    }
}

impl Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    #[inline]
    fn sub(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::sub(self, rhs)
    }
}

impl SubAssign<FieldElement> for FieldElement {
    #[inline]
    fn sub_assign(&mut self, other: FieldElement) {
        *self = *self - other;
    }
}

impl SubAssign<&FieldElement> for FieldElement {
    #[inline]
    fn sub_assign(&mut self, other: &FieldElement) {
        *self = *self - other;
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn mul(self, rhs: FieldElement) -> FieldElement {
        self.relax().mul(&rhs.relax())
    }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn mul(self, rhs: &FieldElement) -> FieldElement {
        self.relax().mul(&rhs.relax())
    }
}

impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;

    #[inline]
    fn mul(self, rhs: &FieldElement) -> FieldElement {
        self.relax().mul(&rhs.relax())
    }
}

impl MulAssign<&FieldElement> for FieldElement {
    #[inline]
    fn mul_assign(&mut self, other: &FieldElement) {
        *self = *self * other;
    }
}

impl MulAssign for FieldElement {
    #[inline]
    fn mul_assign(&mut self, other: FieldElement) {
        *self = *self * other;
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    #[inline]
    fn neg(self) -> FieldElement {
        Self::neg(&self)
    }
}

//
// `core::iter` trait impls
//

impl Sum for FieldElement {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Add::add).unwrap_or(Self::ZERO)
    }
}

impl<'a> Sum<&'a FieldElement> for FieldElement {
    fn sum<I: Iterator<Item = &'a FieldElement>>(iter: I) -> Self {
        iter.copied().sum()
    }
}

impl Product for FieldElement {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Mul::mul).unwrap_or(Self::ONE)
    }
}

impl<'a> Product<&'a FieldElement> for FieldElement {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.copied().product()
    }
}

// `crypto-bigint` trait impls

impl Invert for FieldElement {
    type Output = CtOption<Self>;

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }

    fn invert_vartime(&self) -> CtOption<Self> {
        self.invert_vartime()
    }
}

impl Retrieve for FieldElement {
    type Output = Uint;

    fn retrieve(&self) -> Uint {
        self.to_uint()
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, Uint};
    use hex_literal::hex;

    primefield::test_primefield!(FieldElement, Uint);

    /// Regression test for RustCrypto/elliptic-curves#965
    #[test]
    fn decode_invalid_field_element_returns_err() {
        let overflowing_bytes = hex!(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        );
        let ct_option = FieldElement::from_bytes(&overflowing_bytes.into());
        assert!(bool::from(ct_option.is_none()));
    }

    #[test]
    fn sqn_edge_cases() {
        let a = FieldElement::from_u64(5);
        assert_eq!(a.sqn(0), a);
        assert_eq!(a.sqn(1), a.square());
        assert_eq!(a.sqn(2), a.square().square());
    }
}
