//! Secret keys for elliptic curves: private scalars.

use crate::{error::Error, scalar::Scalar};
use core::convert::{TryFrom, TryInto};
use generic_array::{ArrayLength, GenericArray};

#[cfg(feature = "getrandom")]
use getrandom::getrandom;

/// Secret keys for Weierstrass curves: wrapper around scalar values used as
/// secret keys.
///
/// Prevents accidental exposure and handles zeroization.
pub struct SecretKey<ScalarSize>
where
    ScalarSize: ArrayLength<u8>,
{
    /// Private scalar value
    scalar: Scalar<ScalarSize>,
}

impl<ScalarSize> SecretKey<ScalarSize>
where
    ScalarSize: ArrayLength<u8>,
{
    /// Create a new secret key from a serialized scalar value
    pub fn new(bytes: GenericArray<u8, ScalarSize>) -> Self {
        Self {
            scalar: Scalar::new(bytes),
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
        Self::new(bytes)
    }

    /// Expose the secret [`Scalar`] value this [`SecretKey`] wraps
    pub fn secret_scalar(&self) -> &Scalar<ScalarSize> {
        &self.scalar
    }
}

#[cfg(feature = "zeroize")]
impl<ScalarSize> Drop for SecretKey<ScalarSize>
where
    ScalarSize: ArrayLength<u8>,
{
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.scalar.zeroize();
    }
}

impl<ScalarSize> TryFrom<&[u8]> for SecretKey<ScalarSize>
where
    ScalarSize: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() == ScalarSize::to_usize() {
            Ok(Self::new(GenericArray::clone_from_slice(slice)))
        } else {
            Err(Error)
        }
    }
}
