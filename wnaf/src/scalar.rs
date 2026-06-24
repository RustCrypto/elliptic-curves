use crate::{Digit, WindowSize, le_repr, wnaf_form};
use array::{Array, ArraySize};
use core::marker::PhantomData;
use ff::PrimeField;

/// A "w-ary non-adjacent form" scalar, precomputed to improve the speed of scalar multiplication.
///
/// # Examples
///
/// See [`WnafBase`] for usage examples.
#[derive(Clone, Debug)]
pub struct WnafScalar<F: PrimeField, W: WindowSize, WnafStorage: ArraySize> {
    pub(crate) wnaf: Array<Digit, WnafStorage>,
    pub(crate) digits: usize,
    _field: PhantomData<(F, W)>,
}

impl<F: PrimeField, W: WindowSize, WnafStorage: ArraySize> WnafScalar<F, W, WnafStorage> {
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
    /// Because the number of w-NAF digits — and therefore the number of doublings in the
    /// evaluation loop — is proportional to `bytes.len() * 8`, passing a slice shorter than the
    /// field's canonical representation is faster.
    ///
    /// # Panics
    /// If `bytes*8+1 > WnafStorage::USIZE`.
    #[inline]
    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() * 8 < WnafStorage::USIZE);
        let mut wnaf = Self {
            wnaf: Array::default(),
            digits: 0,
            _field: PhantomData,
        };
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
    /// If `bytes*8+1 > WnafStorage::USIZE`.
    #[inline]
    pub fn init_from_le_bytes(&mut self, bytes: &[u8]) {
        debug_assert!(bytes.len() * 8 < WnafStorage::USIZE);
        self.digits = wnaf_form(&mut self.wnaf, bytes, W::USIZE);
    }
}
