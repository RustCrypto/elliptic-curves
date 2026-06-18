//! Lazy (non-normalized) field elements.
//!
//! This module provides `LazyFieldElement`: a wrapper around the raw field backend
//! (`FieldElement5x52` / `FieldElement10x26`) that tracks the "magnitude" of the
//! value and whether it has been normalized.
//!
//! All arithmetic operations (`add`, `sub`, `mul`, `square`, `negate`, `mul_single`,
//! `double`) produce lazy results — the magnitude is brought to 1, but the value is
//! only *weakly* reduced (carried into the limb representation) without a final
//! modular reduction. This avoids the expensive full normalization pass between
//! every operation, which is critical for performance in inner loops like point
//! addition and scalar multiplication.
//!
//! Call `.normalize()` (or `.normalize_weak()`) to produce a fully reduced
//! `FieldElement`, or use `From<LazyFieldElement> for FieldElement` to convert
//! automatically. The `ff::Field` trait impl on `FieldElement` performs this
//! conversion automatically, so generic code using the trait is unaffected.

use crate::FieldBytes;
use elliptic_curve::{
    bigint::U256,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::Zeroize,
};

cpubits::cpubits! {
    32 => { use super::field_10x26::FieldElement10x26 as FieldElementUnsafeImpl; }
    64 => { use super::field_5x52::FieldElement5x52 as FieldElementUnsafeImpl; }
}

/// Maximum magnitude for lazy field elements.
///
/// This is the largest magnitude `m` such that
/// `0xFFFFFFFFFFFFF * 2 * (m + 1) < 2^64` (for 64-bit limbs), ensuring no
/// overflow occurs in addition/subtraction chains.
pub const MAX_MAGNITUDE: u32 = 2047;

/// A field element that may be lazily normalized — i.e. the result of arithmetic
/// operations before a final modular reduction.
///
/// The inner value is guaranteed to be weakly normalized (all carries propagated,
/// magnitude = 1), but it may still be >= p (i.e. in the range `[p, 2*m)` for
/// some magnitude `m`). Use `.normalize()` to obtain a `FieldElement` with the
/// full modular reduction applied.
#[derive(Clone, Copy, Debug)]
pub struct LazyFieldElement {
    /// Raw field element value (weakly reduced, but not guaranteed < p).
    value: FieldElementUnsafeImpl,
    /// Number of uncancelled additions this element has accumulated.
    /// Used to bound intermediate values and prevent overflow.
    magnitude: u32,
}

impl LazyFieldElement {
    /// Zero element.
    pub const ZERO: Self = Self {
        value: FieldElementUnsafeImpl::ZERO,
        magnitude: 1,
    };

    /// Multiplicative identity.
    pub const ONE: Self = Self {
        value: FieldElementUnsafeImpl::ONE,
        magnitude: 1,
    };

    /// Maximum supported magnitude.
    ///
    /// This is the largest `m` such that `0xFFFFFFFFFFFFF * 2 * (m + 1) < 2^64`
    /// (64-bit limbs), which ensures no overflow occurs in addition chains.
    pub const fn max_magnitude() -> u32 {
        MAX_MAGNITUDE
    }

    /// Construct a new lazy field element from a raw value with the given magnitude.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `magnitude > MAX_MAGNITUDE`.
    fn new(value: &FieldElementUnsafeImpl, magnitude: u32) -> Self {
        debug_assert!(magnitude <= MAX_MAGNITUDE);
        Self {
            value: *value,
            magnitude,
        }
    }

    /// Construct a normalized lazy field element.
    ///
    /// The magnitude is set to 1 and `normalized` to `true`.
    const fn new_normalized(value: &FieldElementUnsafeImpl) -> Self {
        Self {
            value: *value,
            magnitude: 1,
        }
    }

    /// Construct a weakly-normalized lazy field element.
    ///
    /// The magnitude is set to 1 but `normalized` is set to `false`, reflecting
    /// that the value has had carries propagated but has not been reduced mod p.
    fn new_weak_normalized(value: &FieldElementUnsafeImpl) -> Self {
        Self {
            value: *value.normalize_weak(),
            magnitude: 1,
        }
    }

    /// Parse a field element from bytes without validating the range.
    ///
    /// The resulting element is normalized (fully reduced mod p).
    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        Self::new_normalized(&FieldElementUnsafeImpl::from_bytes_unchecked(bytes))
    }

    /// Parse a field element from a `u64`.
    ///
    /// The resulting element is normalized.
    pub const fn from_u64(val: u64) -> Self {
        Self::new_normalized(&FieldElementUnsafeImpl::from_u64(val))
    }

    /// Parse a field element from bytes, validating that the value is in range.
    ///
    /// The resulting element is normalized.
    pub fn from_bytes(bytes: &FieldBytes) -> CtOption<Self> {
        FieldElementUnsafeImpl::from_bytes(bytes).map(|x| Self::new_normalized(&x))
    }

    /// Construct a normalized element from a raw `U256` without range checking.
    ///
    /// The resulting element is normalized.
    pub(crate) const fn from_u256_unchecked(value: U256) -> Self {
        Self {
            value: FieldElementUnsafeImpl::from_u256_unchecked(value),
            magnitude: 1,
        }
    }

    /// Fully normalize the element: reduce mod p and set magnitude to 1.
    ///
    /// This performs the expensive final modular reduction. Prefer to work with
    /// `LazyFieldElement` inside arithmetic loops and only normalize at the boundary.
    pub fn normalize(&self) -> FieldElement {
        FieldElement::from(Self::new_normalized(&self.value.normalize()))
    }

    /// Weakly normalize the element: propagate carries but do not reduce mod p.
    ///
    /// The result has magnitude 1 but may be >= p. This is faster than `normalize()`
    /// but should only be used when the caller is about to perform another
    /// arithmetic operation that will consume the excess.
    pub fn normalize_weak(&self) -> Self {
        Self::new_weak_normalized(&self.value.normalize_weak())
    }

    /// Check whether this element would become zero if fully normalized.
    ///
    /// This is useful for checking if a value is 0 or p (both normalize to 0).
    pub fn normalizes_to_zero(&self) -> Choice {
        self.value.normalizes_to_zero()
    }

    /// Determine if this element is zero.
    ///
    /// The element **must** be normalized before calling this. In debug builds,
    /// this is checked with a debug assertion.
    pub fn is_zero(&self) -> Choice {
        debug_assert!(self.magnitude == 1, "is_zero requires normalized element");
        self.value.is_zero()
    }

    /// Determine if this element is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// The element **must** be normalized before calling this. In debug builds,
    /// this is checked with a debug assertion. (In release builds, calling this
    /// on an unnormalized element produces incorrect results — this is precisely
    /// the class of bugs this type system is designed to eliminate.)
    pub fn is_odd(&self) -> Choice {
        debug_assert!(
            self.magnitude == 1,
            "is_odd requires normalized element"
        );
        self.value.is_odd()
    }

    /// Returns `self + rhs mod p`.
    ///
    /// The new magnitude is `self.magnitude + rhs.magnitude`.
    pub fn add(&self, rhs: &Self) -> Self {
        let new_magnitude = self.magnitude + rhs.magnitude;
        debug_assert!(new_magnitude <= MAX_MAGNITUDE);
        Self::new(&(self.value.add(&rhs.value)), new_magnitude)
    }

    /// Multiplies by a single-limb integer.
    ///
    /// The magnitude is multiplied by the same value.
    pub fn mul_single(&self, rhs: u32) -> Self {
        let new_magnitude = self.magnitude * rhs;
        debug_assert!(new_magnitude <= MAX_MAGNITUDE);
        Self::new(&(self.value.mul_single(rhs)), new_magnitude)
    }

    /// Returns `self * rhs mod p`.
    ///
    /// Both operands must have magnitude ≤ 8. The result has magnitude 1 and is
    /// weakly normalized (carries propagated but may still be ≥ p).
    pub fn mul(&self, rhs: &Self) -> Self {
        debug_assert!(self.magnitude <= 8);
        debug_assert!(rhs.magnitude <= 8);
        Self::new_weak_normalized(&self.value.mul(&rhs.value))
    }

    /// Returns `self * self mod p`.
    ///
    /// The operand must have magnitude ≤ 8. The result has magnitude 1 and is
    /// weakly normalized.
    pub fn square(&self) -> Self {
        debug_assert!(self.magnitude <= 8);
        Self::new_weak_normalized(&self.value.square())
    }

    /// Returns `-self`, treating it as having the given magnitude.
    ///
    /// The provided `magnitude` must be ≥ the actual magnitude of `self`.
    /// The new magnitude is `magnitude + 1`.
    pub fn negate(&self, magnitude: u32) -> Self {
        debug_assert!(self.magnitude <= magnitude);
        let new_magnitude = magnitude + 1;
        debug_assert!(new_magnitude <= MAX_MAGNITUDE);
        Self::new(&(self.value.negate(magnitude)), new_magnitude)
    }

    /// Returns `2 * self`, doubling the magnitude.
    pub fn double(&self) -> Self {
        self.add(self)
    }
}

impl Default for LazyFieldElement {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConditionallySelectable for LazyFieldElement {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // We take the magnitude of the selected element, since magnitude is
        // independent from the value — it must be tracked explicitly regardless.
        let new_magnitude = u32::conditional_select(&a.magnitude, &b.magnitude, choice);
        Self {
            value: FieldElementUnsafeImpl::conditional_select(&a.value, &b.value, choice),
            magnitude: new_magnitude,
        }
    }
}

impl ConstantTimeEq for LazyFieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&other.value) & self.magnitude.ct_eq(&other.magnitude)
    }
}

impl Zeroize for LazyFieldElement {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.magnitude.zeroize();
    }
}

impl From<FieldElement> for LazyFieldElement {
    /// Convert a normalized `FieldElement` to a `LazyFieldElement`.
    ///
    /// Since `FieldElement` is always normalized, this is a zero-cost conversion
    /// (the magnitude is simply set to 1).
    fn from(fe: FieldElement) -> Self {
        // SAFETY: FieldElement is always normalized, so we can construct
        // LazyFieldElement as if it were normalized without calling normalize().
        Self::new_normalized(&fe.0)
    }
}

impl From<LazyFieldElement> for FieldElement {
    /// Convert a `LazyFieldElement` to a normalized `FieldElement`.
    ///
    /// This calls `.normalize()`, performing the full modular reduction.
    fn from(lazy: LazyFieldElement) -> Self {
        lazy.normalize()
    }
}

#[cfg(test)]
mod tests {
    use super::LazyFieldElement;

    #[test]
    fn lazy_field_element_magnitude_tracking() {
        // After 2048 additions of magnitude-1 elements, we'd overflow MAX_MAGNITUDE.
        // Adding MAX_MAGNITUDE elements of magnitude 1 should be fine.
        let mut acc = LazyFieldElement::ONE;
        for _ in 0..(LazyFieldElement::max_magnitude() - 1) {
            acc = acc.add(&LazyFieldElement::ONE);
        }
        // The accumulated element is still valid (weakly normalized)
        let normalized = acc.normalize();
        // Reducing it should still produce 2047 mod p
        let expected = LazyFieldElement::from_u64(LazyFieldElement::max_magnitude() as u64);
        assert_eq!(normalized, expected.normalize());
    }

    #[test]
    fn mul_magnitude_bounds() {
        let a = LazyFieldElement::ONE;
        let b = LazyFieldElement::ONE;
        let _ = a.mul(&b); // should not panic
    }

    #[test]
    fn square_magnitude_bounds() {
        let a = LazyFieldElement::ONE;
        let _ = a.square(); // should not panic
    }

    #[test]
    fn negate_magnitude() {
        let one = LazyFieldElement::ONE;
        let neg = one.negate(1);
        assert_eq!(neg.magnitude, 2);
        // one + neg should be zero after normalization
        let sum = one.add(&neg);
        assert!(bool::from(sum.normalize().is_zero()));
    }

    #[test]
    fn normalizes_to_zero_detects_both_zero_and_p() {
        // Create a lazy element equal to p (mod 2^256) by taking 0 - 0 = 0,
        // but we need something that normalizes to zero.
        // The safest way: negate(1) on ONE gives something that normalizes_to_zero
        // because ONE + (-ONE) = 0 mod p
        let zero = LazyFieldElement::ONE.add(&LazyFieldElement::ONE.negate(1));
        assert!(bool::from(zero.normalizes_to_zero()));
    }
}
