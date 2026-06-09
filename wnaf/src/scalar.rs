use crate::{le_repr, wnaf_form};
use alloc::vec::Vec;
use core::marker::PhantomData;
use ff::PrimeField;

/// A "w-ary non-adjacent form" scalar, that uses precomputation to improve the speed of
/// scalar multiplication.
///
/// # Examples
///
/// See [`WnafBase`] for usage examples.
#[derive(Clone, Debug)]
pub struct WnafScalar<F: PrimeField, const WINDOW_SIZE: usize> {
    pub(crate) wnaf: Vec<i64>,
    field: PhantomData<F>,
}

impl<F: PrimeField, const WINDOW_SIZE: usize> WnafScalar<F, WINDOW_SIZE> {
    /// Computes the w-NAF representation of the given scalar with the specified
    /// `WINDOW_SIZE`.
    pub fn new(scalar: &F) -> Self {
        let mut wnaf = vec![];

        // Compute the w-NAF form of the scalar.
        wnaf_form(&mut wnaf, le_repr(scalar), WINDOW_SIZE);

        WnafScalar {
            wnaf,
            field: PhantomData,
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
    /// Returns `None` if `bytes` is longer than the field's canonical representation, or if
    /// the encoded integer is greater than or equal to the field modulus.
    pub fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        // Validate that `bytes` encodes a canonical field element by round-tripping it through
        // `F::from_repr`, which returns `None` for any integer greater than or equal to the
        // modulus. `from_repr` consumes the canonical representation, assumed big-endian to match
        // `le_repr` below, so reverse the little-endian input into a zero-extended `F::Repr`.
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

        let mut wnaf = vec![];

        // Compute the w-NAF form directly from the provided little-endian bytes.
        wnaf_form(&mut wnaf, bytes, WINDOW_SIZE);

        Some(WnafScalar {
            wnaf,
            field: PhantomData,
        })
    }
}
