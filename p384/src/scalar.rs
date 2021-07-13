//! Scalar type

use crate::{FieldBytes, NistP384, U384};
use core::{
    convert::{TryFrom, TryInto},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use elliptic_curve::{
    bigint::{ArrayEncoding, Limb},
    group::ff::{Field, PrimeField},
    rand_core::RngCore,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    Curve, Error, Result, ScalarArithmetic,
};

impl ScalarArithmetic for NistP384 {
    type Scalar = Scalar;
}

/// Element of the scalar field of the NIST P-384 elliptic curve.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct Scalar(U384);

impl Scalar {
    /// Zero scalar.
    pub const ZERO: Self = Self(U384::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = Self(U384::ONE);

    /// Returns `self + rhs mod n`
    pub const fn add(&self, rhs: &Self) -> Self {
        let (result, carry) = self.0.adc(&rhs.0, Limb::ZERO);

        // Attempt to subtract the modulus, to ensure the result is in the field.
        Self::sub_inner(result, carry, NistP384::ORDER, Limb::ZERO)
    }

    /// Returns `self - rhs mod n`
    pub const fn sub(&self, rhs: &Self) -> Self {
        Self::sub_inner(self.0, Limb::ZERO, rhs.0, Limb::ZERO)
    }

    /// Subtract with an additional extra limb for underflow handling.
    ///
    /// Conditionally adds the modulus (i.e. curve order) on underflow.
    const fn sub_inner(lhs: U384, lhs_hi: Limb, rhs: U384, rhs_hi: Limb) -> Self {
        let (w, borrow) = lhs.sbb(&rhs, Limb::ZERO);
        let borrow = lhs_hi.sbb(rhs_hi, borrow).1;

        // Conditionally add the modulus if underflow occurred on the final limb
        let mut result = U384::ZERO.into_limbs();
        let mut i = 0;
        let mut carry = Limb::ZERO;

        while i < result.len() {
            // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
            // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the
            // modulus.
            let modulus_limb = Limb(NistP384::ORDER.limbs()[i].0 & borrow.0);
            let (l, c) = w.limbs()[i].adc(modulus_limb, carry);
            result[i] = l;
            carry = c;
            i += 1;
        }

        Scalar(U384::new(result))
    }
}

impl Field for Scalar {
    fn random(mut rng: impl RngCore) -> Self {
        let mut bytes = FieldBytes::default();

        // Generate a uniformly random scalar using rejection sampling,
        // which produces a uniformly random distribution of scalars.
        //
        // This method is not constant time, but should be secure so long as
        // rejected RNG outputs are unrelated to future ones (which is a
        // necessary property of a `CryptoRng`).
        loop {
            rng.fill_bytes(&mut bytes);
            if let Some(scalar) = Scalar::from_repr(bytes) {
                return scalar;
            }
        }
    }

    fn zero() -> Self {
        Self::ZERO
    }

    fn one() -> Self {
        Self::ONE
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero().into()
    }

    fn square(&self) -> Self {
        self.mul(self)
    }

    fn double(&self) -> Self {
        self.add(self)
    }

    fn invert(&self) -> CtOption<Self> {
        todo!();
    }

    fn sqrt(&self) -> CtOption<Self> {
        todo!();
    }
}

impl PrimeField for Scalar {
    type Repr = FieldBytes;

    const NUM_BITS: u32 = 384;
    const CAPACITY: u32 = 383;
    const S: u32 = 4; // TODO(tarcieri): this may be wrong

    fn from_repr(bytes: FieldBytes) -> Option<Self> {
        U384::from_be_byte_array(bytes).try_into().ok()
    }

    fn to_repr(&self) -> FieldBytes {
        self.0.to_be_byte_array()
    }

    fn is_odd(&self) -> bool {
        self.0.is_odd().into()
    }

    fn multiplicative_generator() -> Self {
        todo!();
    }

    fn root_of_unity() -> Self {
        todo!();
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar(U384::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Eq for Scalar {}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl PartialOrd for Scalar {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl From<u64> for Scalar {
    fn from(n: u64) -> Scalar {
        Scalar(U384::from(n))
    }
}

impl TryFrom<U384> for Scalar {
    type Error = Error;

    fn try_from(w: U384) -> Result<Self> {
        if w < NistP384::ORDER {
            Ok(Scalar(w))
        } else {
            Err(Error)
        }
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        Scalar::add(&self, &other)
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar::add(&self, other)
    }
}

impl AddAssign<Scalar> for Scalar {
    fn add_assign(&mut self, other: Scalar) {
        *self = Scalar::add(self, &other);
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, other: &Scalar) {
        *self = Scalar::add(self, other);
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        Scalar::sub(&self, &other)
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Scalar::sub(&self, other)
    }
}

impl SubAssign<Scalar> for Scalar {
    fn sub_assign(&mut self, other: Scalar) {
        *self = Scalar::sub(self, &other);
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, other: &Scalar) {
        *self = Scalar::sub(self, other);
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, _other: Scalar) -> Scalar {
        todo!();
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, _other: &Scalar) -> Scalar {
        todo!();
    }
}

impl MulAssign<Scalar> for Scalar {
    fn mul_assign(&mut self, _rhs: Scalar) {
        todo!();
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, _rhs: &Scalar) {
        todo!();
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Scalar::ZERO - self
    }
}

impl<'a> Neg for &'a Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        Scalar::ZERO - self
    }
}
