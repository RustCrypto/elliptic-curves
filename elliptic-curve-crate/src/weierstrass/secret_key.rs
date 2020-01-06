//! Secret keys for Weierstrass curves: private scalars.

use super::{Curve, Scalar};
use crate::error::Error;
use core::convert::{TryFrom, TryInto};
use generic_array::{typenum::Unsigned, GenericArray};

#[cfg(feature = "getrandom")]
use getrandom::getrandom;

/// Secret keys for Weierstrass curves: wrapper around scalar values used as
/// secret keys.
///
/// Prevents accidental exposure and handles zeroization.
pub struct SecretKey<C: Curve> {
    /// Serialized private scalar value as bytes
    bytes: Scalar<C>,
}

impl<C: Curve> SecretKey<C> {
    /// Create a new secret key from a serialized scalar value
    pub fn new(into_bytes: impl Into<GenericArray<u8, C::ScalarSize>>) -> Self {
        Self {
            bytes: into_bytes.into(),
        }
    }

    /// Deserialize this secret key from a bytestring
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        bytes.as_ref().try_into()
    }

    /// Generate a new secret key using the operating system's
    /// cryptographically secure random number generator
    #[cfg(feature = "getrandom")]
    pub fn generate() -> Self {
        let mut bytes = GenericArray::default();
        getrandom(bytes.as_mut_slice()).expect("RNG failure!");
        Self { bytes }
    }

    /// Expose the secret `Scalar<C>` value this `SecretKey` wraps
    pub fn secret_scalar(&self) -> &Scalar<C> {
        &self.bytes
    }
}

impl<C: Curve> Clone for SecretKey<C> {
    fn clone(&self) -> Self {
        Self::new(self.bytes.clone())
    }
}

#[cfg(feature = "zeroize")]
impl<C: Curve> Drop for SecretKey<C> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.as_mut().zeroize();
    }
}

impl<'a, C: Curve> TryFrom<&'a [u8]> for SecretKey<C> {
    type Error = Error;

    fn try_from(slice: &'a [u8]) -> Result<Self, Error> {
        if slice.len() == C::ScalarSize::to_usize() {
            Ok(Self::new(GenericArray::clone_from_slice(slice)))
        } else {
            Err(Error)
        }
    }
}
