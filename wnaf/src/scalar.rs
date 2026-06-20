use crate::{WindowSize, le_repr, wnaf_form};
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
    pub(crate) wnaf: Array<i64, WnafStorage>,
    pub(crate) digits: usize,
    _field: PhantomData<(F, W)>,
}

impl<F: PrimeField, W: WindowSize, WnafStorage: ArraySize> WnafScalar<F, W, WnafStorage> {
    /// Computes the w-NAF representation of the given scalar with window size `W`.
    pub fn new(scalar: &F) -> Self {
        let mut wnaf = Array::from_fn(|_| 0i64);
        let len = wnaf_form(&mut wnaf, le_repr(scalar), W::USIZE);
        WnafScalar {
            wnaf,
            digits: len,
            _field: PhantomData,
        }
    }

    /// Computes the w-NAF representation directly from raw little-endian bytes.
    ///
    /// `bytes` is interpreted as a little-endian unsigned integer (trailing zero bytes may be
    /// omitted), and the resulting [`WnafScalar`] evaluates to that integer times the base.
    /// Because the number of w-NAF digits — and therefore the number of doublings in the
    /// evaluation loop — is proportional to `bytes.len() * 8`, passing a slice shorter than the
    /// field's canonical representation produces a faster scalar.
    ///
    /// This is intended for callers that have already decomposed a scalar into a value smaller
    /// than the field modulus, e.g. the ~128-bit half-scalars produced by a GLV endomorphism
    /// decomposition.
    ///
    /// The encoded integer is validated to be a canonical field element: it must be strictly
    /// less than the field modulus. No modular reduction is performed — a value that is not
    /// already in range is rejected rather than reduced, so the returned [`WnafScalar`] always
    /// evaluates to the integer `bytes` encodes.
    ///
    /// # Errors
    ///
    /// Returns `None` if `bytes` is longer than the field's canonical representation, if the
    /// encoded integer is greater than or equal to the field modulus, or if `bytes.len() * 8 + 1`
    /// exceeds `WnafStorage::USIZE` (which would overflow the fixed-size `wnaf` storage).
    pub fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() * 8 + 1 > WnafStorage::USIZE {
            return None;
        }

        // Validate that `bytes` encodes a canonical field element by round-tripping it through
        // `F::from_repr`, which returns `None` for any integer >= the modulus.
        //
        // `from_repr` consumes the canonical big-endian representation, so reverse the
        // little-endian input into a zero-extended `F::Repr`.
        let mut repr = F::Repr::default();
        let repr_len = repr.as_ref().len();

        // Anything wider than the canonical representation is necessarily out of range.
        if bytes.len() > repr_len {
            return None;
        }

        for (i, &byte) in bytes.iter().enumerate() {
            repr.as_mut()[repr_len - 1 - i] = byte;
        }

        if bool::from(F::from_repr(repr).is_none()) {
            return None;
        }

        let mut wnaf = Array::default();
        let digits = wnaf_form(&mut wnaf, bytes, W::USIZE);

        Some(WnafScalar {
            wnaf,
            digits,
            _field: PhantomData,
        })
    }
}
