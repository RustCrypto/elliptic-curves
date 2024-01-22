//! A debug layer for lazy-reduction field elements making sure
//! they are not misused. Ensures the correct normalization and checks magnitudes in operations.
//! Only enabled when `debug_assertions` feature is on.

use crate::FieldBytes;
use elliptic_curve::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::Zeroize,
};

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))] {
        use super::field_8x32_risc0::FieldElement8x32R0 as FieldElementUnsafeImpl;
    } else if #[cfg(target_pointer_width = "32")] {
        use super::field_10x26::FieldElement10x26 as FieldElementUnsafeImpl;
    } else if #[cfg(target_pointer_width = "64")] {
        use super::field_5x52::FieldElement5x52 as FieldElementUnsafeImpl;
    } else {
        compile_error!("unsupported target word size (i.e. target_pointer_width)");
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FieldElementImpl {
    value: FieldElementUnsafeImpl,
    magnitude: u32,
    normalized: bool,
}

impl FieldElementImpl {
    /// Zero element.
    pub const ZERO: Self = Self {
        value: FieldElementUnsafeImpl::ZERO,
        magnitude: 1,
        normalized: true,
    };

    /// Multiplicative identity.
    pub const ONE: Self = Self {
        value: FieldElementUnsafeImpl::ONE,
        magnitude: 1,
        normalized: true,
    };

    const fn new_normalized(value: &FieldElementUnsafeImpl) -> Self {
        Self {
            value: *value,
            magnitude: 1,
            normalized: true,
        }
    }

    const fn new_weak_normalized(value: &FieldElementUnsafeImpl) -> Self {
        Self {
            value: *value,
            magnitude: 1,
            normalized: false,
        }
    }

    fn new(value: &FieldElementUnsafeImpl, magnitude: u32) -> Self {
        debug_assert!(magnitude <= FieldElementUnsafeImpl::max_magnitude());
        if cfg!(all(target_os = "zkvm", target_arch = "riscv32")) {
            // In the RISC Zero field impl, magnitude is always 1.
            Self {
                value: *value,
                magnitude: 1,
                normalized: false,
            }
        } else {
            Self {
                value: *value,
                magnitude,
                normalized: false,
            }
        }
    }

    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        let value = FieldElementUnsafeImpl::from_bytes_unchecked(bytes);
        Self::new_normalized(&value)
    }

    pub(crate) const fn from_u64(val: u64) -> Self {
        Self::new_normalized(&FieldElementUnsafeImpl::from_u64(val))
    }

    /// Convert a `i64` to a field element.
    /// Returned value may be only weakly normalized.
    pub(crate) const fn from_i64(w: i64) -> Self {
        Self::new_weak_normalized(&FieldElementUnsafeImpl::from_i64(w))
    }

    pub fn from_bytes(bytes: &FieldBytes) -> CtOption<Self> {
        let value = FieldElementUnsafeImpl::from_bytes(bytes);
        CtOption::map(value, |x| Self::new_normalized(&x))
    }

    pub fn to_bytes(self) -> FieldBytes {
        debug_assert!(self.normalized);
        self.value.to_bytes()
    }

    pub fn normalize_weak(&self) -> Self {
        Self::new_weak_normalized(&self.value.normalize_weak())
    }

    pub fn normalize(&self) -> Self {
        Self::new_normalized(&self.value.normalize())
    }

    pub fn normalizes_to_zero(&self) -> Choice {
        self.value.normalizes_to_zero()
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
        let new_magnitude = magnitude + 1;
        debug_assert!(new_magnitude <= FieldElementUnsafeImpl::max_magnitude());
        Self::new(&(self.value.negate(magnitude)), new_magnitude)
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let new_magnitude = self.magnitude + rhs.magnitude;
        debug_assert!(new_magnitude <= FieldElementUnsafeImpl::max_magnitude());
        Self::new(&(self.value.add(&(rhs.value))), new_magnitude)
    }

    pub fn mul_single(&self, rhs: u32) -> Self {
        let new_magnitude = self.magnitude * rhs;
        debug_assert!(new_magnitude <= FieldElementUnsafeImpl::max_magnitude());
        Self::new(&(self.value.mul_single(rhs)), new_magnitude)
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

impl Default for FieldElementImpl {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConditionallySelectable for FieldElementImpl {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // 1. It's debug only, so it shouldn't present a security risk
        // 2. Being normalized does is independent from the field element value;
        //    elements must be normalized explicitly.
        let new_normalized = if bool::from(choice) {
            b.normalized
        } else {
            a.normalized
        };
        Self {
            value: FieldElementUnsafeImpl::conditional_select(&(a.value), &(b.value), choice),
            magnitude: u32::conditional_select(&(a.magnitude), &(b.magnitude), choice),
            normalized: new_normalized,
        }
    }
}

impl ConstantTimeEq for FieldElementImpl {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.value.ct_eq(&(other.value))
            & self.magnitude.ct_eq(&(other.magnitude))
            // See the comment in `conditional_select()`
            & Choice::from((self.normalized == other.normalized) as u8)
    }
}

impl Zeroize for FieldElementImpl {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.magnitude.zeroize();
        self.normalized.zeroize();
    }
}
