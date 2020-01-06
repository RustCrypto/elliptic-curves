//! Scalar wire type

use generic_array::{ArrayLength, GenericArray};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Scalar "wire type": byte array sized appropriately for a given elliptic
/// curve's modulus.
pub struct Scalar<Size: ArrayLength<u8>>(GenericArray<u8, Size>);

impl<Size> Scalar<Size>
where
    Size: ArrayLength<u8>,
{
    /// Create a new scalar from the given byte array
    pub fn new(bytes: GenericArray<u8, Size>) -> Self {
        Scalar(bytes)
    }
}

impl<Size> AsRef<GenericArray<u8, Size>> for Scalar<Size>
where
    Size: ArrayLength<u8>,
{
    fn as_ref(&self) -> &GenericArray<u8, Size> {
        &self.0
    }
}

impl<Size> Clone for Scalar<Size>
where
    Size: ArrayLength<u8>,
{
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl<Size> From<GenericArray<u8, Size>> for Scalar<Size>
where
    Size: ArrayLength<u8>,
{
    fn from(bytes: GenericArray<u8, Size>) -> Self {
        Scalar(bytes)
    }
}

#[cfg(feature = "zeroize")]
impl<Size> Zeroize for Scalar<Size>
where
    Size: ArrayLength<u8>,
{
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize();
    }
}
