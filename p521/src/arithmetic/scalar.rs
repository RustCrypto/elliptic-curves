//! secp521r1 scalar field elements.
//!
//! Arithmetic implementations are provided by `primefield` and `crypto-bigint`.

use crate::{FieldBytes, FieldBytesEncoding, NistP521, ORDER_HEX, Uint};
use elliptic_curve::{
    Curve as _,
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

primefield::monty_field_params! {
    name: ScalarParams,
    modulus: ORDER_HEX,
    uint: Uint,
    byte_order: primefield::ByteOrder::BigEndian,
    multiplicative_generator: 2,
    doc: "Montgomery parameters for the NIST P-521 scalar modulus `n`."
}

primefield::monty_field_element! {
    name: Scalar,
    params: ScalarParams,
    uint: Uint,
    doc: "Element in the NIST P-521 scalar field modulo `n`."
}

primefield::monty_field_arithmetic! {
    name: Scalar,
    params: ScalarParams,
    uint: Uint
}

elliptic_curve::scalar_impls!(NistP521, Scalar);

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
        const MODULUS_SHR1: Uint = NistP521::ORDER.as_ref().shr_vartime(1);
        self.to_canonical().ct_gt(&MODULUS_SHR1)
    }
}

impl Reduce<Uint> for Scalar {
    fn reduce(w: &Uint) -> Self {
        let (r, underflow) = w.borrowing_sub(&NistP521::ORDER, Limb::ZERO);
        let underflow = Choice::from((underflow.0 >> (Limb::BITS - 1)) as u8);
        Self::from_uint_unchecked(Uint::conditional_select(w, &r, !underflow))
    }
}

impl Reduce<FieldBytes> for Scalar {
    #[inline]
    fn reduce(bytes: &FieldBytes) -> Self {
        <Self as Reduce<Uint>>::reduce(&FieldBytesEncoding::<NistP521>::decode_field_bytes(bytes))
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
    use super::{Scalar, Uint};
    use elliptic_curve::ff::PrimeField;
    primefield::test_primefield_constants!(Scalar, Uint);
    primefield::test_field_identity!(Scalar);
    primefield::test_field_invert!(Scalar);
    //primefield::test_field_sqrt!(Scalar); TODO(tarcieri): working sqrt impl
}
