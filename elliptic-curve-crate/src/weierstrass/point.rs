//! Compressed and uncompressed Weierstrass elliptic curve points.
//!
//! Serialized according to the `Elliptic-Curve-Point-to-Octet-String`
//! algorithm described in SEC 1: Elliptic Curve Cryptography (Version 2.0)
//! section 2.3.3 (page 10):
//!
//! <https://www.secg.org/sec1-v2.pdf>

use super::Curve;
use crate::ScalarBytes;
use core::ops::Add;
use generic_array::{
    typenum::{Unsigned, U1},
    ArrayLength, GenericArray,
};

/// Size of a compressed elliptic curve point for the given curve when
/// serialized using `Elliptic-Curve-Point-to-Octet-String` encoding
/// (including leading `0x02` or `0x03` tag byte).
pub type CompressedPointSize<ScalarSize> = <ScalarSize as Add<U1>>::Output;

/// Size of an uncompressed elliptic curve point for the given curve when
/// serialized using the `Elliptic-Curve-Point-to-Octet-String` encoding
/// (including leading `0x04` tag byte).
pub type UncompressedPointSize<ScalarSize> = <<ScalarSize as Add>::Output as Add<U1>>::Output;

/// Compressed elliptic curve points serialized according to the
/// `Elliptic-Curve-Point-to-Octet-String` algorithm.
///
/// See section 2.3.3 of SEC 1: Elliptic Curve Cryptography (Version 2.0):
///
/// <https://www.secg.org/sec1-v2.pdf>
#[derive(Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct CompressedPoint<C: Curve>
where
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    /// Raw serialized bytes of the compressed point
    bytes: GenericArray<u8, CompressedPointSize<C::ScalarSize>>,
}

impl<C: Curve> CompressedPoint<C>
where
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    /// Compress and serialize an elliptic curve point from its affine coordinates
    pub fn from_affine_coords(
        x: &ScalarBytes<C::ScalarSize>,
        y: &ScalarBytes<C::ScalarSize>,
    ) -> Self {
        // Is the y-coordinate odd in the SEC-1 sense: `self mod 2 == 1`?
        let is_y_odd = y.as_ref().last().expect("last byte") & 1 == 1;
        let mut bytes = GenericArray::default();
        bytes[0] = if is_y_odd { 0x03 } else { 0x02 };
        bytes[1..].copy_from_slice(x);
        Self { bytes }
    }

    /// Create a new compressed elliptic curve point
    pub fn from_bytes<B>(into_bytes: B) -> Option<Self>
    where
        B: Into<GenericArray<u8, CompressedPointSize<C::ScalarSize>>>,
    {
        let bytes = into_bytes.into();
        let tag_byte = bytes.as_ref()[0];

        if tag_byte == 0x02 || tag_byte == 0x03 {
            Some(Self { bytes })
        } else {
            None
        }
    }

    /// Borrow byte slice containing compressed curve point
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Obtain owned array containing compressed curve point
    #[inline]
    pub fn into_bytes(self) -> GenericArray<u8, CompressedPointSize<C::ScalarSize>> {
        self.bytes
    }
}

impl<C: Curve> AsRef<[u8]> for CompressedPoint<C>
where
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<C: Curve> Copy for CompressedPoint<C>
where
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    <CompressedPointSize<C::ScalarSize> as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C: Curve> Clone for CompressedPoint<C>
where
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    fn clone(&self) -> Self {
        Self::from_bytes(self.bytes.clone()).unwrap()
    }
}

/// Uncompressed elliptic curve points serialized according to the
/// `Elliptic-Curve-Point-to-Octet-String` algorithm.
///
/// See section 2.3.3 of SEC 1: Elliptic Curve Cryptography (Version 2.0):
///
/// <https://www.secg.org/sec1-v2.pdf>
#[derive(Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct UncompressedPoint<C: Curve>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    /// Raw serialized bytes of the uncompressed point
    bytes: GenericArray<u8, UncompressedPointSize<C::ScalarSize>>,
}

impl<C: Curve> UncompressedPoint<C>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    /// Serialize an elliptic curve point from its affine coordinates
    pub fn from_affine_coords(
        x: &ScalarBytes<C::ScalarSize>,
        y: &ScalarBytes<C::ScalarSize>,
    ) -> Self {
        let scalar_size = C::ScalarSize::to_usize();
        let mut bytes = GenericArray::default();
        bytes[0] = 0x04;
        bytes[1..(scalar_size + 1)].copy_from_slice(x);
        bytes[(scalar_size + 1)..].copy_from_slice(y);
        Self { bytes }
    }

    /// Create a new uncompressed elliptic curve point
    pub fn from_bytes<B>(into_bytes: B) -> Option<Self>
    where
        B: Into<GenericArray<u8, UncompressedPointSize<C::ScalarSize>>>,
    {
        let bytes = into_bytes.into();

        if bytes.get(0) == Some(&0x04) {
            Some(Self { bytes })
        } else {
            None
        }
    }

    /// Borrow byte slice containing uncompressed curve point
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert public key into owned byte array
    #[inline]
    pub fn into_bytes(self) -> GenericArray<u8, UncompressedPointSize<C::ScalarSize>> {
        self.bytes
    }
}

impl<C: Curve> AsRef<[u8]> for UncompressedPoint<C>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<C: Curve> Copy for UncompressedPoint<C>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    <UncompressedPointSize<C::ScalarSize> as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C: Curve> Clone for UncompressedPoint<C>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    fn clone(&self) -> Self {
        Self::from_bytes(self.bytes.clone()).unwrap()
    }
}
