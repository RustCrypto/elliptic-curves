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

#[cfg(doc)]
use core::ops::{Add, Mul, Neg, Sub};

primefield::monty_field_params!(
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: U256,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 3,
    fe_name: "Scalar",
    doc: "Bign P-256 scalar modulus"
);

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
pub struct Scalar(pub(super) primefield::MontyFieldElement<ScalarParams, { ScalarParams::LIMBS }>);

primefield::field_element_type!(Scalar, ScalarParams, U256);

primefield::fiat_field_arithmetic!(
    Scalar,
    ScalarParams,
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
        const MODULUS_SHR1: U256 = BignP256::ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl Reduce<U256> for Scalar {
    fn reduce(w: &U256) -> Self {
        let (r, underflow) = w.borrowing_sub(&BignP256::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U256::conditional_select(w, &r, !underflow))
    }
}

impl Reduce<FieldBytes> for Scalar {
    #[inline]
    fn reduce(bytes: &FieldBytes) -> Self {
        let w = <U256 as FieldBytesEncoding<BignP256>>::decode_field_bytes(bytes);
        Self::reduce(&w)
    }
}

impl TryFrom<U256> for Scalar {
    type Error = Error;

    fn try_from(w: U256) -> Result<Self> {
        Self::try_from(&w)
    }
}

impl TryFrom<&U256> for Scalar {
    type Error = Error;

    fn try_from(w: &U256) -> Result<Self> {
        Self::from_uint(w).into_option().ok_or(Error)
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, U256};
    primefield::test_primefield!(Scalar, U256);
}
