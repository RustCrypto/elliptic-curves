//! secp521r1 scalar field elements.
//!
//! Arithmetic implementations are provided by `primefield` and `crypto-bigint`.
//!
//! # Constant-time
//!
//! Operations in this module that operate on secret scalars (e.g. private keys,
//! ECDSA nonces) are intended to be constant-time: comparisons use
//! `ConstantTimeEq`/`ct_eq`, selection uses `ConditionallySelectable`, and
//! reduction uses `conditional_select` so that control flow does not depend on
//! secret data.

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
    multiplicative_generator: 3,
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
    /// Reduce an integer modulo the curve order. Constant-time in the value `w`.
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
    use elliptic_curve::subtle::ConstantTimeEq;
    primefield::test_primefield!(Scalar, Uint);

    /// Constant-time equality: same value must yield Choice(1), different values Choice(0).
    #[test]
    fn scalar_ct_eq() {
        let z = Scalar::ZERO;
        let o = Scalar::ONE;
        assert!(bool::from(z.ct_eq(&z)));
        assert!(bool::from(o.ct_eq(&o)));
        assert!(!bool::from(z.ct_eq(&o)));
        assert!(!bool::from(o.ct_eq(&z)));
    }
}
