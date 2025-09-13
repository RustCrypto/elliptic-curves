//! secp224r1 scalar field elements.
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

#[cfg_attr(target_pointer_width = "32", path = "scalar/p224_scalar_32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar/p224_scalar_64.rs")]
#[allow(
    clippy::identity_op,
    clippy::needless_lifetimes,
    clippy::unnecessary_cast,
    clippy::too_many_arguments
)]
#[allow(dead_code)] // TODO(tarcieri): remove this when we can use `const _` to silence warnings
mod scalar_impl;

use self::scalar_impl::*;
use crate::{FieldBytes, FieldBytesEncoding, NistP224, ORDER_HEX, Uint};
use elliptic_curve::{
    Curve as _, Error, Result,
    bigint::Limb,
    ff::PrimeField,
    ops::Reduce,
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

primefield::monty_field_params!(
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: Uint,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 2,
    fe_name: "Scalar",
    doc: "P-224 scalar modulus"
);

/// Scalars are elements in the finite field modulo `n`.
///
/// # Trait impls
///
/// Much of the important functionality of scalars is provided by traits from
/// the [`ff`](https://docs.rs/ff/) crate, which is re-exported as
/// `p224::elliptic_curve::ff`:
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
/// # Warning: `sqrt` unimplemented!
///
/// `Scalar::sqrt` has not been implemented and will panic if invoked!
///
/// See [RustCrypto/elliptic-curves#847] for more info.
///
/// [RustCrypto/elliptic-curves#847]: https://github.com/RustCrypto/elliptic-curves/issues/847
#[derive(Clone, Copy, PartialOrd, Ord)]
pub struct Scalar(primefield::MontyFieldElement<ScalarParams, { ScalarParams::LIMBS }>);

primefield::monty_field_element!(Scalar, ScalarParams, Uint);

primefield::monty_field_fiat_arithmetic!(
    Scalar,
    ScalarParams,
    Uint,
    fiat_p224_scalar_non_montgomery_domain_field_element,
    fiat_p224_scalar_montgomery_domain_field_element,
    fiat_p224_scalar_from_montgomery,
    fiat_p224_scalar_to_montgomery,
    fiat_p224_scalar_add,
    fiat_p224_scalar_sub,
    fiat_p224_scalar_mul,
    fiat_p224_scalar_opp,
    fiat_p224_scalar_square,
    fiat_p224_scalar_divstep_precomp,
    fiat_p224_scalar_divstep,
    fiat_p224_scalar_msat,
    fiat_p224_scalar_selectznz
);

elliptic_curve::scalar_impls!(NistP224, Scalar);

impl Scalar {
    /// Atkin algorithm for q mod 8 = 5
    /// <https://eips.ethereum.org/assets/eip-3068/2012-685_Square_Root_Even_Ext.pdf>
    /// (page 10, algorithm 3)
    pub fn sqrt(&self) -> CtOption<Self> {
        let w = &[
            0xc27ba528ab8b8547,
            0xffffe2d45c171e07,
            0xffffffffffffffff,
            0x1fffffff,
        ];
        let t = Self::from_u64(2).pow_vartime(w);
        let a1 = self.pow_vartime(w);
        let a0 = (a1.square() * self).square();
        let b = t * a1;
        let ab = self * &b;
        let i = Self::from_u64(2) * ab * b;
        let x = ab * (i - Self::ONE);
        CtOption::new(x, !a0.ct_eq(&-Self::ONE))
    }
}

impl AsRef<Scalar> for Scalar {
    fn as_ref(&self) -> &Scalar {
        self
    }
}

impl FromUintUnchecked for Scalar {
    type Uint = Uint;

    fn from_uint_unchecked(uint: Self::Uint) -> Self {
        Self::from_uint_unchecked(uint)
    }
}

impl IsHigh for Scalar {
    fn is_high(&self) -> Choice {
        const MODULUS_SHR1: Uint = NistP224::ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl Reduce<Uint> for Scalar {
    fn reduce(w: &Uint) -> Self {
        let (r, underflow) = w.borrowing_sub(&NistP224::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(Uint::conditional_select(w, &r, !underflow))
    }
}

impl Reduce<FieldBytes> for Scalar {
    #[inline]
    fn reduce(bytes: &FieldBytes) -> Self {
        let w = <Uint as FieldBytesEncoding<NistP224>>::decode_field_bytes(bytes);
        Self::reduce(&w)
    }
}

impl TryFrom<Uint> for Scalar {
    type Error = Error;

    fn try_from(w: Uint) -> Result<Self> {
        Self::try_from(&w)
    }
}

impl TryFrom<&Uint> for Scalar {
    type Error = Error;

    fn try_from(w: &Uint) -> Result<Self> {
        Self::from_uint(w).into_option().ok_or(Error)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        ScalarValue::from(self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(ScalarValue::deserialize(deserializer)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Scalar, Uint};
    primefield::test_primefield!(Scalar, Uint);
}
