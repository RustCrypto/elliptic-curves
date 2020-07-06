#[cfg(debug_assertions)]
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(not(debug_assertions))]
#[cfg(feature = "field-5x52")]
pub use super::field_5x52::FieldElement5x52 as FieldElementImpl;

#[cfg(debug_assertions)]
#[cfg(feature = "field-5x52")]
use super::field_5x52::FieldElement5x52 as FieldElementUnsafeImpl;

#[cfg(debug_assertions)]
#[cfg(test)]
use num_bigint::{BigUint, ToBigUint};


#[cfg(debug_assertions)]
#[derive(Clone, Copy, Debug)]
pub struct FieldElementImpl {
    value: FieldElementUnsafeImpl,
    magnitude: u32,
    normalized: bool
    }


#[cfg(debug_assertions)]
impl ConditionallySelectable for FieldElementImpl {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // 1. It's debug only, so it shouldn't present a security risk
        // 2. Being normalized does is independent from the field element value;
        //    elements must be normalized explicitly.
        let new_normalized = if bool::from(choice) { b.normalized } else { a.normalized };
        Self {
            value: FieldElementUnsafeImpl::conditional_select(&(a.value), &(b.value), choice),
            magnitude: u32::conditional_select(&(a.magnitude), &(b.magnitude), choice),
            normalized: new_normalized
            }
    }
}


#[cfg(debug_assertions)]
impl ConstantTimeEq for FieldElementImpl {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&(other.value))
            & self.magnitude.ct_eq(&(other.magnitude))
            // See the comment in `conditional_select()`
            & Choice::from((self.normalized == other.normalized) as u8)
    }
}


#[cfg(debug_assertions)]
impl FieldElementImpl {

    const fn new_normalized(value: &FieldElementUnsafeImpl) -> Self {
        Self {
            value: *value,
            magnitude: 1,
            normalized: true}
    }

    const fn new_weak_normalized(value: &FieldElementUnsafeImpl) -> Self {
        Self {
            value: *value,
            magnitude: 1u32,
            normalized: false}
    }

    fn new(value: &FieldElementUnsafeImpl, magnitude: u32) -> Self {
        debug_assert!(magnitude < 2048);
        Self {
            value: *value,
            magnitude: magnitude,
            normalized: false}
    }

    pub const fn zero() -> Self {
        Self::new_normalized(&FieldElementUnsafeImpl::zero())
    }

    /// Returns the multiplicative identity.
    pub const fn one() -> Self {
        Self::new_normalized(&FieldElementUnsafeImpl::one())
    }

    /// Attempts to parse the given byte array as an SEC-1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Self> {
        let value = FieldElementUnsafeImpl::from_bytes(bytes);
        CtOption::map(value, |x| { Self::new_normalized(&x) })
    }

    /// Returns the SEC-1 encoding of this field element.
    pub fn to_bytes(&self) -> [u8; 32] {
        debug_assert!(self.normalized);
        self.value.to_bytes()
    }

    pub fn normalize_weak(&self) -> Self {
        Self::new_weak_normalized(&self.value.normalize_weak())
    }

    pub fn normalize(&self) -> Self {
        Self::new_normalized(&self.value.normalize())
    }

    pub fn to_words(&self) -> [u64; 4] {
        debug_assert!(self.normalized);
        self.value.to_words()
    }

    pub const fn from_words_unchecked(words: [u64; 4]) -> Self {
        let value = FieldElementUnsafeImpl::from_words_unchecked(words);
        Self::new_normalized(&value)
    }

    pub fn from_words(words: [u64; 4]) -> CtOption<Self> {
        let value = FieldElementUnsafeImpl::from_words(words);
        CtOption::map(value, |x| { Self::new_normalized(&x) })
    }

    pub fn is_zero(&self) -> Choice {
        debug_assert!(self.normalized);
        self.value.is_zero()
    }

    pub fn is_odd(&self) -> Choice {
        debug_assert!(self.normalized);
        self.value.is_odd()
    }

    pub fn negate(&self, magnitude: u32) -> Self {
        debug_assert!(self.magnitude <= magnitude);
        Self::new(&(self.value.negate(magnitude)), magnitude + 1)
    }

    pub fn add(&self, rhs: &Self) -> Self {
        Self::new(&(self.value.add(&(rhs.value))), self.magnitude + rhs.magnitude)
    }

    pub fn double(&self) -> Self {
        Self::new(&(self.value.double()), self.magnitude * 2)
    }

    pub fn mul_single(&self, rhs: u32) -> Self {
        Self::new(&(self.value.mul_single(rhs)), self.magnitude * rhs)
    }

    /// Returns self * rhs mod p
    pub fn mul(&self, rhs: &Self) -> Self {
        debug_assert!(self.magnitude <= 8);
        debug_assert!(rhs.magnitude <= 8);
        Self::new_weak_normalized(&(self.value.mul(&(rhs.value))))
    }

    /// Returns self * self mod p
    pub fn square(&self) -> Self {
        debug_assert!(self.magnitude <= 8);
        Self::new_weak_normalized(&(self.value.square()))
    }
}


#[cfg(debug_assertions)]
impl Default for FieldElementImpl {
    fn default() -> Self {
        Self::zero()
    }
}


#[cfg(debug_assertions)]
#[cfg(test)]
impl From<&BigUint> for FieldElementImpl {
    fn from(x: &BigUint) -> Self {
        Self::new_normalized(&FieldElementUnsafeImpl::from(x))
    }
}


#[cfg(debug_assertions)]
#[cfg(test)]
impl ToBigUint for FieldElementImpl {
    fn to_biguint(&self) -> Option<BigUint> {
        debug_assert!(self.normalized);
        self.value.to_biguint()
    }
}
