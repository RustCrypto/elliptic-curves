//! bign-curve256v1 scalar field elements.

#![allow(clippy::arithmetic_side_effects)]

#[cfg_attr(target_pointer_width = "32", path = "scalar/bignp256_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/bignp256_scalar_64.rs")]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod scalar_impl;

use self::scalar_impl::*;
use crate::{BignP256, FieldBytes, ORDER_HEX, U256};
use elliptic_curve::{
    Curve as _, FieldBytesEncoding,
    bigint::Limb,
    ff::PrimeField,
    ops::Reduce,
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption},
};

#[cfg(doc)]
use core::ops::{Add, Mul, Neg, Sub};

primefield::monty_field_params! {
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: U256,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 3,
    doc: "Montgomery parameters for the bign-curve256v1 scalar modulus"
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: U256,
    doc: "Element in the bign-curve256v1 scalar field modulo n"
}

primefield::monty_field_fiat_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U256,
    non_mont: fiat_bignp256_scalar_non_montgomery_domain_field_element,
    mont: fiat_bignp256_scalar_montgomery_domain_field_element,
    from_mont: fiat_bignp256_scalar_from_montgomery,
    to_mont: fiat_bignp256_scalar_to_montgomery,
    add: fiat_bignp256_scalar_add,
    sub: fiat_bignp256_scalar_sub,
    mul: fiat_bignp256_scalar_mul,
    neg: fiat_bignp256_scalar_opp,
    square: fiat_bignp256_scalar_square,
    divstep_precomp: fiat_bignp256_scalar_divstep_precomp,
    divstep: fiat_bignp256_scalar_divstep,
    msat: fiat_bignp256_scalar_msat,
    selectnz: fiat_bignp256_scalar_selectznz
}

elliptic_curve::scalar_impls!(BignP256, Scalar);

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

#[cfg(test)]
mod tests {
    use super::{Scalar, U256};
    primefield::test_primefield!(Scalar, U256);
}
