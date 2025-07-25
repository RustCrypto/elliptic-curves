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

#![allow(clippy::unusual_byte_groupings)]

#[cfg_attr(target_pointer_width = "32", path = "scalar/p384_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/p384_scalar_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::too_many_arguments,
    clippy::unnecessary_cast
)]
mod scalar_impl;

use self::scalar_impl::*;
use crate::{FieldBytes, NistP384, ORDER_HEX, U384};
use elliptic_curve::{
    Curve as _, Error, FieldBytesEncoding, Result,
    bigint::{ArrayEncoding, Limb},
    ff::PrimeField,
    ops::{Reduce, ReduceNonZero},
    scalar::{FromUintUnchecked, IsHigh},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption},
};

#[cfg(feature = "bits")]
use {
    crate::ScalarBits,
    elliptic_curve::{bigint::Word, group::ff::PrimeFieldBits},
};

#[cfg(feature = "serde")]
use {
    elliptic_curve::ScalarPrimitive,
    serdect::serde::{Deserialize, Serialize, de, ser},
};

#[cfg(doc)]
use core::ops::{Add, Mul, Neg, Sub};

/// Scalars are elements in the finite field modulo `n`.
///
/// # Trait impls
///
/// Much of the important functionality of scalars is provided by traits from
/// the [`ff`](https://docs.rs/ff/) crate, which is re-exported as
/// `p384::elliptic_curve::ff`:
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
#[derive(Clone, Copy, PartialOrd, Ord)]
pub struct Scalar(U384);

primefield::field_element_type!(
    Scalar,
    FieldBytes,
    U384,
    NistP384::ORDER,
    FieldBytesEncoding::<NistP384>::decode_field_bytes,
    FieldBytesEncoding::<NistP384>::encode_field_bytes
);

primefield::fiat_field_arithmetic!(
    Scalar,
    FieldBytes,
    U384,
    fiat_p384_scalar_non_montgomery_domain_field_element,
    fiat_p384_scalar_montgomery_domain_field_element,
    fiat_p384_scalar_from_montgomery,
    fiat_p384_scalar_to_montgomery,
    fiat_p384_scalar_add,
    fiat_p384_scalar_sub,
    fiat_p384_scalar_mul,
    fiat_p384_scalar_opp,
    fiat_p384_scalar_square,
    fiat_p384_scalar_divstep_precomp,
    fiat_p384_scalar_divstep,
    fiat_p384_scalar_msat,
    fiat_p384_scalar_selectznz
);

elliptic_curve::scalar_impls!(NistP384, Scalar);

impl Scalar {
    /// Compute modular square root.
    pub fn sqrt(&self) -> CtOption<Self> {
        // p mod 4 = 3 -> compute sqrt(x) using x^((p+1)/4) =
        // x^9850501549098619803069760025035903451269934817616361666986726319906914849778315892349739077038073728388608413485661
        let t1 = *self;
        let t10 = t1.square();
        let t11 = *self * t10;
        let t101 = t10 * t11;
        let t111 = t10 * t101;
        let t1001 = t10 * t111;
        let t1011 = t10 * t1001;
        let t1101 = t10 * t1011;
        let t1111 = t10 * t1101;
        let t11110 = t1111.square();
        let t11111 = t1 * t11110;
        let t1111100 = t11111.sqn(2);
        let t11111000 = t1111100.square();
        let i14 = t11111000.square();
        let i20 = i14.sqn(5) * i14;
        let i31 = i20.sqn(10) * i20;
        let i58 = (i31.sqn(4) * t11111000).sqn(21) * i31;
        let i110 = (i58.sqn(3) * t1111100).sqn(47) * i58;
        let x194 = i110.sqn(95) * i110 * t1111;
        let i225 = ((x194.sqn(6) * t111).sqn(3) * t11).sqn(7);
        let i235 = ((t1101 * i225).sqn(6) * t1101).square() * t1;
        let i258 = ((i235.sqn(11) * t11111).sqn(2) * t1).sqn(8);
        let i269 = ((t1101 * i258).sqn(2) * t11).sqn(6) * t1011;
        let i286 = ((i269.sqn(4) * t111).sqn(6) * t11111).sqn(5);
        let i308 = ((t1011 * i286).sqn(10) * t1101).sqn(9) * t1101;
        let i323 = ((i308.sqn(4) * t1011).sqn(6) * t1001).sqn(3);
        let i340 = ((t1 * i323).sqn(7) * t1011).sqn(7) * t101;
        let i357 = ((i340.sqn(5) * t111).sqn(5) * t1111).sqn(5);
        let i369 = ((t1011 * i357).sqn(4) * t1011).sqn(5) * t111;
        let i387 = ((i369.sqn(3) * t11).sqn(7) * t11).sqn(6);
        let i397 = ((t1011 * i387).sqn(4) * t101).sqn(3) * t11;
        let i413 = ((i397.sqn(4) * t11).sqn(4) * t11).sqn(6);
        let i427 = ((t101 * i413).sqn(5) * t101).sqn(6) * t1011;
        let x = i427.sqn(3) * t101;
        CtOption::new(x, x.square().ct_eq(&t1))
    }

    fn sqn(&self, n: usize) -> Self {
        let mut x = *self;
        for _ in 0..n {
            x = x.square();
        }
        x
    }
}

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
        const MODULUS_SHR1: U384 = NistP384::ORDER.shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const MODULUS: &'static str = ORDER_HEX;
    const CAPACITY: u32 = 383;
    const NUM_BITS: u32 = 384;
    const TWO_INV: Self = Self::from_u64(2).invert_unchecked();
    const MULTIPLICATIVE_GENERATOR: Self = Self::from_u64(2);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self = Self::from_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
    );
    const ROOT_OF_UNITY_INV: Self = Self::ROOT_OF_UNITY.invert_unchecked();
    const DELTA: Self = Self::from_u64(4);

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

#[cfg(feature = "bits")]
impl PrimeFieldBits for Scalar {
    type ReprBits = [Word; U384::LIMBS];

    fn to_le_bits(&self) -> ScalarBits {
        self.to_canonical().to_words().into()
    }

    fn char_le_bits() -> ScalarBits {
        NistP384::ORDER.to_words().into()
    }
}

impl Reduce<U384> for Scalar {
    type Bytes = FieldBytes;

    fn reduce(w: U384) -> Self {
        let (r, underflow) = w.borrowing_sub(&NistP384::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(U384::conditional_select(&w, &r, !underflow))
    }

    #[inline]
    fn reduce_bytes(bytes: &FieldBytes) -> Self {
        Self::reduce(U384::from_be_byte_array(*bytes))
    }
}

impl ReduceNonZero<U384> for Scalar {
    fn reduce_nonzero(w: U384) -> Self {
        const ORDER_MINUS_ONE: U384 = NistP384::ORDER.wrapping_sub(&U384::ONE);
        let (r, underflow) = w.borrowing_sub(&ORDER_MINUS_ONE, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self(U384::conditional_select(&w, &r, !underflow).wrapping_add(&U384::ONE))
    }

    fn reduce_nonzero_bytes(bytes: &FieldBytes) -> Self {
        Self::reduce_nonzero(U384::from_be_byte_array(*bytes))
    }
}

impl TryFrom<U384> for Scalar {
    type Error = Error;

    fn try_from(w: U384) -> Result<Self> {
        Option::from(Self::from_uint(w)).ok_or(Error)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        ScalarPrimitive::from(self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(ScalarPrimitive::deserialize(deserializer)?.into())
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
        assert_eq!(Scalar::reduce_nonzero_bytes(&Array::default()).0, U384::ONE,);
        assert_eq!(Scalar::reduce_nonzero(U384::ONE).0, U384::from_u8(2),);
        assert_eq!(Scalar::reduce_nonzero(U384::from_u8(2)).0, U384::from_u8(3),);

        assert_eq!(Scalar::reduce_nonzero(NistP384::ORDER).0, U384::from_u8(2),);
        assert_eq!(
            Scalar::reduce_nonzero(NistP384::ORDER.wrapping_sub(&U384::from_u8(1))).0,
            U384::ONE,
        );
        assert_eq!(
            Scalar::reduce_nonzero(NistP384::ORDER.wrapping_sub(&U384::from_u8(2))).0,
            NistP384::ORDER.wrapping_sub(&U384::ONE),
        );
        assert_eq!(
            Scalar::reduce_nonzero(NistP384::ORDER.wrapping_sub(&U384::from_u8(3))).0,
            NistP384::ORDER.wrapping_sub(&U384::from_u8(2)),
        );

        assert_eq!(
            Scalar::reduce_nonzero(NistP384::ORDER.wrapping_add(&U384::ONE)).0,
            U384::from_u8(3),
        );
        assert_eq!(
            Scalar::reduce_nonzero(NistP384::ORDER.wrapping_add(&U384::from_u8(2))).0,
            U384::from_u8(4),
        );
    }

    prop_compose! {
        fn non_zero_scalar()(bytes in any::<[u8; 48]>()) -> NonZeroScalar {
            NonZeroScalar::reduce_nonzero_bytes(&bytes.into())
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
