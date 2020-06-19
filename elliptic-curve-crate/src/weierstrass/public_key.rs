//! Public keys for Weierstrass curves: wrapper around compressed or
//! uncompressed elliptic curve points.

use super::Curve;
use super::{
    point::{
        CompressedCurvePoint, CompressedPointSize, UncompressedCurvePoint, UncompressedPointSize,
    },
    FixedBaseScalarMul,
};
use crate::SecretKey;
use core::fmt::{self, Debug};
use core::ops::Add;
use generic_array::{
    typenum::{Unsigned, U1},
    ArrayLength, GenericArray,
};
use subtle::CtOption;

/// Size of an untagged point for given elliptic curve.
// TODO(tarcieri): const generics
pub type UntaggedPointSize<ScalarSize> = <ScalarSize as Add>::Output;

/// Public keys for Weierstrass curves
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum PublicKey<C: Curve>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    /// Compressed Weierstrass elliptic curve point
    Compressed(CompressedCurvePoint<C>),

    /// Uncompressed Weierstrass elliptic curve point
    Uncompressed(UncompressedCurvePoint<C>),
}

impl<C: Curve> PublicKey<C>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    /// Decode public key from an elliptic curve point
    /// (compressed or uncompressed) encoded using the
    /// `Elliptic-Curve-Point-to-Octet-String` algorithm described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        let slice = bytes.as_ref();
        let length = slice.len();

        if length == <CompressedPointSize<C::ScalarSize>>::to_usize() {
            let array = GenericArray::clone_from_slice(slice);
            let point = CompressedCurvePoint::from_bytes(array)?;
            Some(PublicKey::Compressed(point))
        } else if length == <UncompressedPointSize<C::ScalarSize>>::to_usize() {
            let array = GenericArray::clone_from_slice(slice);
            let point = UncompressedCurvePoint::from_bytes(array)?;
            Some(PublicKey::Uncompressed(point))
        } else {
            None
        }
    }

    /// Decode public key from an compressed elliptic curve point
    /// encoded using the `Elliptic-Curve-Point-to-Octet-String` algorithm
    /// described in SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.3 (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    pub fn from_compressed_point<B>(into_bytes: B) -> Option<Self>
    where
        B: Into<GenericArray<u8, CompressedPointSize<C::ScalarSize>>>,
    {
        CompressedCurvePoint::from_bytes(into_bytes).map(PublicKey::Compressed)
    }

    /// Decode public key from a raw uncompressed point serialized
    /// as a bytestring, without a `0x04`-byte tag.
    ///
    /// This will be twice the modulus size, or 1-byte smaller than the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding i.e
    /// with the leading `0x04` byte in that encoding removed.
    pub fn from_untagged_point(bytes: &GenericArray<u8, UntaggedPointSize<C::ScalarSize>>) -> Self
    where
        <C::ScalarSize as Add>::Output: ArrayLength<u8>,
    {
        let mut tagged_bytes = GenericArray::default();
        tagged_bytes.as_mut_slice()[0] = 0x04;
        tagged_bytes.as_mut_slice()[1..].copy_from_slice(bytes.as_ref());

        PublicKey::Uncompressed(UncompressedCurvePoint::from_bytes(tagged_bytes).unwrap())
    }

    /// Obtain public key as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Compressed(ref point) => point.as_bytes(),
            PublicKey::Uncompressed(ref point) => point.as_bytes(),
        }
    }
}

impl<C: Curve> PublicKey<C>
where
    C: FixedBaseScalarMul,
    <C::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    /// Compute the [`PublicKey`] for the provided [`SecretKey`].
    ///
    /// The `compress` flag requests point compression.
    pub fn from_secret_key(
        secret_key: &SecretKey<C::ScalarSize>,
        compress: bool,
    ) -> CtOption<Self> {
        C::mul_base(secret_key.secret_scalar()).map(|affine_point| {
            if compress {
                CompressedCurvePoint::from_affine_point(affine_point).into()
            } else {
                UncompressedCurvePoint::from_affine_point(affine_point).into()
            }
        })
    }
}

impl<C: Curve> AsRef<[u8]> for PublicKey<C>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C: Curve> Copy for PublicKey<C>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    <CompressedPointSize<C::ScalarSize> as ArrayLength<u8>>::ArrayType: Copy,
    <UncompressedPointSize<C::ScalarSize> as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C: Curve> Debug for PublicKey<C>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey<{:?}>({:?})", C::default(), self.as_ref())
    }
}

impl<C: Curve> From<CompressedCurvePoint<C>> for PublicKey<C>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    fn from(point: CompressedCurvePoint<C>) -> Self {
        PublicKey::Compressed(point)
    }
}

impl<C: Curve> From<UncompressedCurvePoint<C>> for PublicKey<C>
where
    <C::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    fn from(point: UncompressedCurvePoint<C>) -> Self {
        PublicKey::Uncompressed(point)
    }
}
