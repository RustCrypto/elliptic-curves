//! secp384r1 scalar field elements.
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

#[cfg(all(not(p384_backend = "bignum"), target_pointer_width = "32"))]
use fiat_crypto::p384_scalar_32::*;
#[cfg(all(not(p384_backend = "bignum"), target_pointer_width = "64"))]
use fiat_crypto::p384_scalar_64::*;

use crate::{FieldBytes, NistP384, ORDER_HEX, U384};
use elliptic_curve::{
    Curve as _,
    bigint::{ArrayEncoding, Limb},
    ff::PrimeField,
    ops::{Reduce, ReduceNonZero},
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption},
};

#[cfg(feature = "serde")]
use {
    elliptic_curve::ScalarValue,
    serdect::serde::{Deserialize, Serialize, de, ser},
};

#[cfg(doc)]
use core::ops::{Add, Mul, Neg, Sub};

primefield::monty_field_params! {
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: U384,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 2,
    doc: "Montgomery parameters for the NIST P-384 scalar modulus `n`."
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: U384,
    doc: "Element in the NIST P-384 scalar field modulo `n`."
}

#[cfg(p384_backend = "bignum")]
primefield::monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U384
}

#[cfg(not(p384_backend = "bignum"))]
primefield::monty_field_fiat_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U384,
    non_mont: fiat_p384_scalar_non_montgomery_domain_field_element,
    mont: fiat_p384_scalar_montgomery_domain_field_element,
    from_mont: fiat_p384_scalar_from_montgomery,
    to_mont: fiat_p384_scalar_to_montgomery,
    add: fiat_p384_scalar_add,
    sub: fiat_p384_scalar_sub,
    mul: fiat_p384_scalar_mul,
    neg: fiat_p384_scalar_opp,
    square: fiat_p384_scalar_square,
    divstep_precomp: fiat_p384_scalar_divstep_precomp,
    divstep: fiat_p384_scalar_divstep,
    msat: fiat_p384_scalar_msat,
    selectnz: fiat_p384_scalar_selectznz
}

elliptic_curve::scalar_impls!(NistP384, Scalar);

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U384;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U384 = NistP384::ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl Reduce<U384> for Scalar {
    fn reduce(w: &U384) -> Self {
        let (r, underflow) = w.borrowing_sub(&NistP384::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U384::conditional_select(w, &r, !underflow))
    }
}

impl Reduce<FieldBytes> for Scalar {
    #[inline]
    fn reduce(bytes: &FieldBytes) -> Self {
        Self::reduce(&U384::from_be_byte_array(*bytes))
    }
}

impl ReduceNonZero<U384> for Scalar {
    fn reduce_nonzero(w: &U384) -> Self {
        const ORDER_MINUS_ONE: U384 = NistP384::ORDER.as_ref().wrapping_sub(&U384::ONE);
        let (r, underflow) = w.borrowing_sub(&ORDER_MINUS_ONE, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(
            U384::conditional_select(w, &r, !underflow).wrapping_add(&U384::ONE),
        )
    }
}

impl ReduceNonZero<FieldBytes> for Scalar {
    #[inline]
    fn reduce_nonzero(bytes: &FieldBytes) -> Self {
        Self::reduce_nonzero(&U384::from_be_byte_array(*bytes))
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
    use super::{Scalar, U384};
    use crate::{FieldBytes, NistP384, NonZeroScalar};
    use elliptic_curve::{
        Curve,
        array::Array,
        ff::PrimeField,
        ops::{BatchInvert, ReduceNonZero},
    };
    use proptest::{prelude::any, prop_compose, proptest};

    primefield::test_primefield!(Scalar, U384);

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

    #[test]
    fn reduce_nonzero() {
        assert_eq!(
            Scalar::reduce_nonzero(&Array::default()).to_canonical(),
            U384::ONE
        );
        assert_eq!(
            Scalar::reduce_nonzero(&U384::ONE).to_canonical(),
            U384::from_u8(2)
        );
        assert_eq!(
            Scalar::reduce_nonzero(&U384::from_u8(2)).to_canonical(),
            U384::from_u8(3),
        );

        assert_eq!(
            Scalar::reduce_nonzero(NistP384::ORDER.as_ref()).to_canonical(),
            U384::from_u8(2),
        );
        assert_eq!(
            Scalar::reduce_nonzero(&NistP384::ORDER.wrapping_sub(&U384::from_u8(1))).to_canonical(),
            U384::ONE,
        );
        assert_eq!(
            Scalar::reduce_nonzero(&NistP384::ORDER.wrapping_sub(&U384::from_u8(2))).to_canonical(),
            NistP384::ORDER.wrapping_sub(&U384::ONE),
        );
        assert_eq!(
            Scalar::reduce_nonzero(&NistP384::ORDER.wrapping_sub(&U384::from_u8(3))).to_canonical(),
            NistP384::ORDER.wrapping_sub(&U384::from_u8(2)),
        );

        assert_eq!(
            Scalar::reduce_nonzero(&NistP384::ORDER.wrapping_add(&U384::ONE)).to_canonical(),
            U384::from_u8(3),
        );
        assert_eq!(
            Scalar::reduce_nonzero(&NistP384::ORDER.wrapping_add(&U384::from_u8(2))).to_canonical(),
            U384::from_u8(4),
        );
    }

    prop_compose! {
        fn non_zero_scalar()(bytes in any::<[u8; 48]>()) -> NonZeroScalar {
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
