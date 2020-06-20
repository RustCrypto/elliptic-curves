//! Elliptic curves in short Weierstrass form

use core::{fmt::Debug, ops::Add};
use generic_array::{
    typenum::{Unsigned, U1},
    ArrayLength,
};

#[cfg(docsrs)]
use crate::ScalarBytes;

/// Elliptic curve in short Weierstrass form
pub trait Curve: Clone + Debug + Default + Eq + Ord + Send + Sync {
    /// Size of [`ScalarBytes`] for this curve, i.e. a serialized integer
    /// modulo p (i.e. the curve's order).
    type ScalarSize: ArrayLength<u8> + Add + Add<U1> + Eq + Ord + Unsigned;
}

/// Alias for [`SecretKey`] type for a given Weierstrass curve
pub type SecretKey<C> = crate::secret_key::SecretKey<<C as Curve>::ScalarSize>;
