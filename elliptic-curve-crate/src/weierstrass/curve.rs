//! Registry of elliptic curves in short Weierstrass form

// Weierstrass curves
pub mod nistp256;
pub mod nistp384;
pub mod secp256k1;

pub use self::{nistp256::NistP256, nistp384::NistP384, secp256k1::Secp256k1};

use core::{fmt::Debug, ops::Add};
use generic_array::{
    typenum::{Unsigned, U1},
    ArrayLength, GenericArray,
};

/// Elliptic curve in short Weierstrass form
pub trait Curve: Clone + Debug + Default + Eq + Ord + Send + Sync {
    /// Size of an integer modulo p (i.e. the curve's order) when serialized
    /// as octets (i.e. bytes).
    type ScalarSize: ArrayLength<u8> + Add + Add<U1> + Eq + Ord + Unsigned;
}

/// Alias for `GenericArray` which is the size of the curve's scalar
pub type Scalar<C> = GenericArray<u8, <C as Curve>::ScalarSize>;
