//! bign-curve256v1 scalar field elements.

#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::identity_op,
    clippy::arithmetic_side_effects,
    clippy::too_many_arguments,
    clippy::unnecessary_cast
)]

#[cfg_attr(target_pointer_width = "32", path = "scalar/bign256_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/bign256_scalar_64.rs")]
mod scalar_impl;

use self::scalar_impl::*;
use crate::{BignP256, FieldBytes, ORDER_HEX, U256};
use elliptic_curve::{
    Curve as _, Error, FieldBytesEncoding, Result,
    bigint::Limb,
    ff::PrimeField,
    ops::Reduce,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption},
};

#[cfg(feature = "bits")]
use {
    crate::ScalarBits,
    elliptic_curve::{bigint::Word, group::ff::PrimeFieldBits},
};

#[cfg(doc)]
use core::ops::{Add, Mul, Neg, Sub};

/// Scalars are elements in the finite field modulo `n`.
///
/// # Trait impls
///
/// Much of the important functionality of scalars is provided by traits from
/// the [`ff`](https://docs.rs/ff/) crate, which is re-exported as
/// `bign256::elliptic_curve::ff`:
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
#[derive(Clone, Copy, PartialOrd, Ord)]
pub struct Scalar(pub U256);

primefield::field_element_type!(
    Scalar,
    FieldBytes,
    U256,
    BignP256::ORDER,
    FieldBytesEncoding::<BignP256>::decode_field_bytes,
    FieldBytesEncoding::<BignP256>::encode_field_bytes
);

primefield::fiat_field_arithmetic!(
    Scalar,
    FieldBytes,
    U256,
    fiat_bign256_scalar_non_montgomery_domain_field_element,
    fiat_bign256_scalar_montgomery_domain_field_element,
    fiat_bign256_scalar_from_montgomery,
    fiat_bign256_scalar_to_montgomery,
    fiat_bign256_scalar_add,
    fiat_bign256_scalar_sub,
    fiat_bign256_scalar_mul,
    fiat_bign256_scalar_opp,
    fiat_bign256_scalar_square,
    fiat_bign256_scalar_divstep_precomp,
    fiat_bign256_scalar_divstep,
    fiat_bign256_scalar_msat,
    fiat_bign256_scalar_selectznz
);

elliptic_curve::scalar_impls!(BignP256, Scalar);

impl Scalar {
    /// Returns the square root of self mod p, or `None` if no square root
    /// exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Because p ≡ 3 mod 4, sqrt can be done with only one
        // exponentiation via the computation of self^((p + 1) // 4) (mod p).
        let sqrt = self.pow_vartime(&[
            0x1f96afe6498f5982,
            0xf65723b5837ed37f,
            0xffffffffffffffff,
            0x3fffffffffffffff,
        ]);
        CtOption::new(sqrt, (sqrt * sqrt).ct_eq(self))
    }
}

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U256;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U256 = BignP256::ORDER.shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        Self::from_bytes(&repr)
    }

    fn to_repr(&self) -> Self::Repr {
        self.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        self.is_odd()
    }

    const MODULUS: &'static str = ORDER_HEX;
    const NUM_BITS: u32 = 256;
    const CAPACITY: u32 = 255;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(3);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self =
        Self::from_hex("ffffffffffffffffffffffffffffffffd95c8ed60dfb4dfc7e5abf99263d6606");
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    const DELTA: Self = Self::from_u64(9);
}

#[cfg(feature = "bits")]
impl PrimeFieldBits for Scalar {
    type ReprBits = [Word; U256::LIMBS];

    fn to_le_bits(&self) -> ScalarBits {
        self.to_canonical().to_words().into()
    }

    fn char_le_bits() -> ScalarBits {
        BignP256::ORDER.to_words().into()
    }
}

impl Reduce<U256> for Scalar {
    type Bytes = FieldBytes;

    fn reduce(w: U256) -> Self {
        let (r, underflow) = w.borrowing_sub(&BignP256::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U256::conditional_select(&w, &r, !underflow))
    }

    #[inline]
    fn reduce_bytes(bytes: &FieldBytes) -> Self {
        let w = <U256 as FieldBytesEncoding<BignP256>>::decode_field_bytes(bytes);
        Self::reduce(w)
    }
}

impl TryFrom<U256> for Scalar {
    type Error = Error;

    fn try_from(w: U256) -> Result<Self> {
        Option::from(Self::from_uint(w)).ok_or(Error)
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, U256};
    primefield::test_primefield!(Scalar, U256);
}
