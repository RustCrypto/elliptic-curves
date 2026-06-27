use crate::{Digit, WindowSize, WnafSize, le_repr, wnaf_form};
use array::{Array, typenum::Unsigned};
use core::marker::PhantomData;
use ff::PrimeField;

#[cfg(doc)]
use crate::WnafBase;

/// A "w-ary non-adjacent form" scalar, precomputed to improve the speed of scalar multiplication.
///
/// The w-NAF representation is represented by a table of [`Digit`]s which includes one for each
/// bit of the original scalar, plus an additional bit for any remaining carry, i.e.
/// `F::NUM_BITS + 1`.
///
/// # Examples
///
/// See [`WnafBase`] for usage examples.
#[derive(Clone, Debug, Default)]
pub struct WnafScalar<F: PrimeField + WnafSize, W: WindowSize> {
    pub(crate) wnaf: Array<Digit, F::StorageSize>,
    pub(crate) digits: usize,
    _field: PhantomData<(F, W)>,
}

impl<F: PrimeField + WnafSize, W: WindowSize> WnafScalar<F, W> {
    /// Computes the w-NAF representation of the given scalar with window size `W`.
    #[inline]
    pub fn new(scalar: &F) -> Self {
        Self::from_le_bytes(le_repr(scalar).as_ref())
    }

    /// Computes the w-NAF representation directly from raw little-endian bytes.
    ///
    /// `bytes` is interpreted as a little-endian unsigned integer (trailing zero bytes may be
    /// omitted), and the resulting [`WnafScalar`] evaluates to that integer times the base.
    ///
    /// Because the number of w-NAF digits, and therefore the number of doublings, is proportional
    /// to `bytes.len() * 8`, passing a slice shorter than the field's canonical representation is
    /// faster.
    ///
    /// # Panics
    /// If `bytes*8+1 > S::USIZE`.
    #[inline]
    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        let mut wnaf = Self::default();
        wnaf.init_from_le_bytes(bytes);
        wnaf
    }

    /// Initialize w-NAF representation directly from raw little-endian bytes, for an already
    /// allocated [`WnafScalar`].
    ///
    /// This is the equivalent of [`WnafScalar::from_le_bytes`] for reusing an existing value.
    /// See that method for full documentation.
    ///
    /// # Panics
    /// If `bytes*8+1 > S::USIZE`.
    #[inline]
    pub fn init_from_le_bytes(&mut self, bytes: &[u8]) {
        debug_assert_eq!(F::NUM_BITS + 1, F::StorageSize::U32);
        debug_assert!(bytes.len() * 8 + 1 <= F::StorageSize::USIZE);
        self.digits = wnaf_form(&mut self.wnaf, bytes, W::USIZE);
    }
}
