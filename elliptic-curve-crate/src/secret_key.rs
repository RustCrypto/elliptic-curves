//! Secret keys for elliptic curves (i.e. private scalars)
//!
//! The [`SecretKey`] type wraps the [`ScalarBytes`] byte array type with
//! a wrapper designed to prevent unintentional exposure of the scalar
//! value (e.g. via `Debug` or other logging).
//!
//! When the `zeroize` feature of this crate is enabled, it also handles
//! zeroing it out of memory securely on drop.

use crate::{error::Error, ScalarBytes};
use core::{
    convert::{TryFrom, TryInto},
    fmt,
};
use generic_array::ArrayLength;

/// Secret keys.
///
/// In elliptic curve cryptography, secret keys are concretely privately known
/// scalar values.
///
/// This type wraps a (serialized) scalar value, helping to prevent accidental
/// exposure and securely erasing the value from memory when dropped
/// (when the `zeroize` feature of this crate is enabled).
pub struct SecretKey<ScalarSize>
where
    ScalarSize: ArrayLength<u8>,
{
    /// Private scalar value
    scalar: ScalarBytes<ScalarSize>,
}

impl<ScalarSize> SecretKey<ScalarSize>
where
    ScalarSize: ArrayLength<u8>,
{
    /// Create a new secret key from a serialized scalar value
    pub fn new(bytes: ScalarBytes<ScalarSize>) -> Self {
        Self { scalar: bytes }
    }

    /// Deserialize this secret key from a bytestring
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        bytes.as_ref().try_into()
    }

    /// Expose the secret [`ScalarBytes`] value this [`SecretKey`] wraps
    pub fn secret_scalar(&self) -> &ScalarBytes<ScalarSize> {
        &self.scalar
    }
}

impl<ScalarSize> TryFrom<&[u8]> for SecretKey<ScalarSize>
where
    ScalarSize: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() == ScalarSize::to_usize() {
            Ok(SecretKey {
                scalar: ScalarBytes::clone_from_slice(slice),
            })
        } else {
            Err(Error)
        }
    }
}

impl<ScalarSize> fmt::Debug for SecretKey<ScalarSize>
where
    ScalarSize: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey<U{}>{{ ... }}", ScalarSize::to_usize())
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
