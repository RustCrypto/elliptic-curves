//! secp521r1 scalar field elements.
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

#[cfg_attr(target_pointer_width = "32", path = "scalar/p521_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/p521_scalar_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[rustfmt::skip]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod scalar_impl;

use self::scalar_impl::*;
use crate::{FieldBytes, NistP521, ORDER_HEX, U576};
use elliptic_curve::{
    Curve as _, FieldBytesEncoding,
    bigint::NonZero,
    ff::PrimeField,
    ops::{Reduce, ReduceNonZero},
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, CtOption},
};
use primefield::MontyFieldElement;

#[cfg(feature = "serde")]
use {
    elliptic_curve::ScalarValue,
    serdect::serde::{Deserialize, Serialize, de, ser},
};

#[cfg(doc)]
use core::ops::{Add, Mul, Neg, Sub};

primefield::monty_field_params!(
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: U576,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 3,
    doc: "Montgomery parameters for the NIST P-521 scalar modulus `n`."
);

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: U576,
    doc: "Element in the NIST P-521 scalar field modulo `n`."
}

primefield::monty_field_fiat_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: U576,
    non_mont: fiat_p521_scalar_non_montgomery_domain_field_element,
    mont: fiat_p521_scalar_montgomery_domain_field_element,
    from_mont: fiat_p521_scalar_from_montgomery,
    to_mont: fiat_p521_scalar_to_montgomery,
    add: fiat_p521_scalar_add,
    sub: fiat_p521_scalar_sub,
    mul: fiat_p521_scalar_mul,
    neg: fiat_p521_scalar_opp,
    square: fiat_p521_scalar_square,
    divstep_precomp: fiat_p521_scalar_divstep_precomp,
    divstep: fiat_p521_scalar_divstep,
    msat: fiat_p521_scalar_msat,
    selectnz: fiat_p521_scalar_selectznz
}

elliptic_curve::scalar_impls!(NistP521, Scalar);

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = U576;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: U576 = NistP521::ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl Reduce<U576> for Scalar {
    fn reduce(w: &U576) -> Self {
        Self(MontyFieldElement::from_uint_reduced(w))
    }
}

impl Reduce<FieldBytes> for Scalar {
    #[inline]
    fn reduce(bytes: &FieldBytes) -> Self {
        let w = <U576 as FieldBytesEncoding<NistP521>>::decode_field_bytes(bytes);
        Self::reduce(&w)
    }
}

impl ReduceNonZero<U576> for Scalar {
    fn reduce_nonzero(w: &U576) -> Self {
        const ORDER_MINUS_ONE: U576 = NistP521::ORDER.as_ref().wrapping_sub(&U576::ONE);
        let r = w.rem(&NonZero::new(ORDER_MINUS_ONE).unwrap());
        Self::from_uint_unchecked(r.wrapping_add(&U576::ONE))
    }
}

impl ReduceNonZero<FieldBytes> for Scalar {
    #[inline]
    fn reduce_nonzero(bytes: &FieldBytes) -> Self {
        let w = <U576 as FieldBytesEncoding<NistP521>>::decode_field_bytes(bytes);
        Self::reduce_nonzero(&w)
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
    use crate::{FieldBytes, NistP521, NonZeroScalar};

    use super::{Scalar, U576};
    use elliptic_curve::{
        Curve,
        array::Array,
        ops::{BatchInvert, ReduceNonZero},
    };
    use proptest::{prelude::any, prop_compose, proptest};

    primefield::test_primefield!(Scalar, U576);

    #[test]
    fn reduce_nonzero() {
        assert_eq!(
            U576::from(Scalar::reduce_nonzero(&Array::default())),
            U576::ONE,
        );
        assert_eq!(
            U576::from(Scalar::reduce_nonzero(&U576::ONE)),
            U576::from_u8(2),
        );
        assert_eq!(
            U576::from(Scalar::reduce_nonzero(&U576::from_u8(2))),
            U576::from_u8(3),
        );

        assert_eq!(
            U576::from(Scalar::reduce_nonzero(NistP521::ORDER.as_ref())),
            U576::from_u8(2),
        );
        assert_eq!(
            U576::from(Scalar::reduce_nonzero(
                &NistP521::ORDER.wrapping_sub(&U576::from_u8(1))
            )),
            U576::ONE,
        );
        assert_eq!(
            U576::from(Scalar::reduce_nonzero(
                &NistP521::ORDER.wrapping_sub(&U576::from_u8(2))
            )),
            NistP521::ORDER.wrapping_sub(&U576::ONE),
        );
        assert_eq!(
            U576::from(Scalar::reduce_nonzero(
                &NistP521::ORDER.wrapping_sub(&U576::from_u8(3))
            )),
            NistP521::ORDER.wrapping_sub(&U576::from_u8(2)),
        );

        assert_eq!(
            U576::from(Scalar::reduce_nonzero(
                &NistP521::ORDER.wrapping_add(&U576::ONE)
            )),
            U576::from_u8(3),
        );
        assert_eq!(
            U576::from(Scalar::reduce_nonzero(
                &NistP521::ORDER.wrapping_add(&U576::from_u8(2))
            )),
            U576::from_u8(4),
        );

        assert_eq!(
            U576::from(Scalar::reduce_nonzero(
                &NistP521::ORDER.wrapping_mul(&U576::from_u8(3))
            )),
            U576::from_u8(4),
        );
    }

    prop_compose! {
        fn non_zero_scalar()(bytes in any::<[u8; 66]>()) -> NonZeroScalar {
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
