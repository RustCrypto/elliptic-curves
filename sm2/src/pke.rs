//! SM2 Encryption Algorithm (SM2) as defined in [draft-shen-sm2-ecdsa § 5].
//!
//! ## Usage
//!
//! The `DecryptingKey` struct is used for decrypting messages that were encrypted using the SM2
//! encryption algorithm.
//!
//! It is initialized with a `SecretKey` or a non-zero scalar value and can decrypt ciphertexts
//! using the specified decryption mode.
//!
#![cfg_attr(
    all(feature = "pke", feature = "getrandom", feature = "der"),
    doc = "```"
)]
#![cfg_attr(
    not(all(feature = "pke", feature = "getrandom", feature = "der")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires the `pke` and `getrandom` crate features are enabled
//! use sm2::{
//!     elliptic_curve::{Generate, common::getrandom::SysRng},
//!     pke::{EncryptingKey, Mode},
//!     SecretKey, PublicKey
//! };
//!
//! // Encrypting
//! let secret_key = SecretKey::generate(); // serialize with `::to_bytes()`
//! let public_key = secret_key.public_key();
//! let encrypting_key = EncryptingKey::new_with_mode(public_key, Mode::C1C2C3);
//! let plaintext = b"plaintext";
//! let ciphertext = encrypting_key.encrypt(&mut SysRng, plaintext)?;
//!
//! use sm2::pke::DecryptingKey;
//! // Decrypting
//! let decrypting_key = DecryptingKey::new_with_mode(secret_key.to_nonzero_scalar(), Mode::C1C2C3);
//! assert_eq!(decrypting_key.decrypt(&ciphertext)?, plaintext);
//!
//! // Encrypting ASN.1 DER
//! let ciphertext = encrypting_key.encrypt_der(&mut SysRng, plaintext)?;
//!
//! // Decrypting ASN.1 DER
//! assert_eq!(decrypting_key.decrypt_der(&ciphertext)?, plaintext);
//!
//! Ok(())
//! # }
//!  ```

#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, vec, vec::Vec};

#[cfg(feature = "der")]
use der::{
    Decode, DecodeValue, Encode, EncodeValue, Length, Reader, Sequence, Tag, Writer,
    asn1::{OctetStringRef, UintRef},
};
#[cfg(feature = "der")]
use elliptic_curve::array::Array;
use elliptic_curve::{
    CurveArithmetic, Error, Group, PrimeField, Result,
    array::typenum::Unsigned,
    ops::Reduce,
    sec1::{self, Coordinates, FromSec1Point, ModulusSize, Sec1Point, ToSec1Point},
};
use sm3::digest::{FixedOutputReset, Output, OutputSizeUser, Update};

#[cfg(feature = "arithmetic")]
mod decrypting;
#[cfg(feature = "arithmetic")]
mod encrypting;

#[cfg(feature = "arithmetic")]
pub use self::{decrypting::DecryptingKey, encrypting::EncryptingKey};

/// Modes for the cipher encoding/decoding.
#[derive(Clone, Copy, Debug, Default)]
pub enum Mode {
    /// old mode
    C1C2C3,
    /// new mode
    /// The standard data layout used for SM2 encryption/decryption.
    /// C1C3C2 is the default per modern specifications.
    #[default]
    C1C3C2,
}

/// Represents a cipher structure containing encryption-related data (asn.1 format).
///
/// The `Cipher` structure includes the coordinates of the elliptic curve point (`x`, `y`),
/// the digest of the message, and the encrypted cipher text.
#[derive(Debug)]
pub struct Cipher<'a, C: CurveArithmetic = crate::Sm2, D: OutputSizeUser = sm3::Sm3> {
    c1: C::AffinePoint,
    #[cfg(feature = "alloc")]
    c2: Cow<'a, [u8]>,
    #[cfg(not(feature = "alloc"))]
    c2: &'a [u8],
    c3: Output<D>,
}

impl<'a, C, D> Cipher<'a, C, D>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
    D: OutputSizeUser,
{
    /// Convert lifetime to 'static.
    ///
    /// Note: copying may occur.
    #[cfg(feature = "alloc")]
    pub fn cats_to_static(self) -> Cipher<'static, C, D> {
        let Cipher { c1, c2, c3 } = self;
        let c2 = match c2 {
            Cow::Borrowed(v) => Cow::Owned(v.to_vec()),
            Cow::Owned(v) => Cow::Owned(v),
        };
        Cipher { c1, c2, c3 }
    }

    /// Decode from slice
    pub fn from_slice(cipher: &'a [u8], mode: Mode) -> Result<Self> {
        let tag = sec1::Tag::from_u8(cipher.first().cloned().ok_or(Error)?)?;
        let c1_len = tag.message_len(C::FieldBytesSize::USIZE);
        let digest_size = D::output_size();

        if cipher.len() < c1_len + digest_size {
            return Err(Error);
        }

        // B1: get 𝐶1 from 𝐶
        let (c1, c) = cipher.split_at(c1_len);
        // verify that point c1 satisfies the elliptic curve
        let encoded_c1 = Sec1Point::<C>::from_bytes(c1)?;
        let c1: C::AffinePoint =
            Option::from(FromSec1Point::from_sec1_point(&encoded_c1)).ok_or(Error)?;
        // B2: compute point 𝑆 = [ℎ]𝐶1
        let scalar: C::Scalar = Reduce::<C::Uint>::reduce(&C::Uint::from(C::Scalar::S));

        let s: C::ProjectivePoint = C::ProjectivePoint::from(c1) * scalar;
        if s.is_identity().into() {
            return Err(Error);
        }

        let (c2, c3_buf) = match mode {
            Mode::C1C3C2 => {
                let (c3, c2) = c.split_at(digest_size);
                (c2, c3)
            }
            Mode::C1C2C3 => c.split_at(c.len() - digest_size),
        };

        let mut c3 = Output::<D>::default();
        c3.clone_from_slice(c3_buf);

        #[cfg(feature = "alloc")]
        let c2 = Cow::Borrowed(c2);

        Ok(Self { c1, c2, c3 })
    }

    /// Length after conversion to standard ciphertext format
    pub fn message_len(&self, compressed: bool) -> usize {
        let tag = if compressed {
            sec1::Tag::Compact
        } else {
            sec1::Tag::Uncompressed
        };
        tag.message_len(C::FieldBytesSize::USIZE) + self.c2.len() + self.c3.len()
    }

    /// Encode to Vec
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self, mode: Mode, compressed: bool) -> Result<Vec<u8>> {
        let mut result = vec![0; self.message_len(compressed)];
        self.to_slice(mode, &mut result, compressed)?;
        Ok(result)
    }

    /// Encode to slice
    pub fn to_slice<'b>(
        &self,
        mode: Mode,
        out_buf: &'b mut [u8],
        compressed: bool,
    ) -> Result<&'b [u8]> {
        let point = self.c1.to_sec1_point(compressed);
        let len = self.message_len(compressed);
        if out_buf.len() < len {
            return Err(Error);
        }
        let buf = &mut out_buf[..len];
        match mode {
            Mode::C1C2C3 => {
                buf[..point.len()].clone_from_slice(point.as_bytes());
                let buf = &mut buf[point.len()..];

                buf[..self.c2.len()].clone_from_slice(self.c2.as_ref());
                let buf = &mut buf[self.c2.len()..];

                buf.clone_from_slice(&self.c3);
            }
            Mode::C1C3C2 => {
                buf[..point.len()].clone_from_slice(point.as_bytes());
                let buf = &mut buf[point.len()..];

                buf[..self.c3.len()].clone_from_slice(&self.c3);
                let buf = &mut buf[self.c3.len()..];

                buf.clone_from_slice(self.c2.as_ref());
            }
        }

        Ok(&out_buf[..len])
    }

    /// Get C1
    pub fn c1(&self) -> &C::AffinePoint {
        &self.c1
    }
    /// Get C2
    pub fn c2(&self) -> &[u8] {
        #[cfg(feature = "alloc")]
        return &self.c2;
        #[cfg(not(feature = "alloc"))]
        return self.c2;
    }
    /// Get C3
    pub fn c3(&self) -> &Output<D> {
        &self.c3
    }
}
#[cfg(feature = "der")]
impl<'a, C, D> Sequence<'a> for Cipher<'a, C, D>
where
    C: CurveArithmetic,
    D: OutputSizeUser,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
{
}
#[cfg(feature = "der")]
impl<C, D> EncodeValue for Cipher<'_, C, D>
where
    C: CurveArithmetic,
    D: OutputSizeUser,
    C::AffinePoint: ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
{
    fn value_len(&self) -> der::Result<Length> {
        #[cfg(feature = "alloc")]
        let c2 = self.c2.as_ref();
        #[cfg(not(feature = "alloc"))]
        let c2 = self.c2;

        let point = self.c1.to_sec1_point(false);
        let (x, y) = match point.coordinates() {
            Coordinates::Uncompressed { x, y } => (x, y),
            _ => unreachable!(),
        };
        UintRef::new(x)?.encoded_len()?
            + UintRef::new(y)?.encoded_len()?
            + OctetStringRef::new(&self.c3)?.encoded_len()?
            + OctetStringRef::new(c2)?.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        #[cfg(feature = "alloc")]
        let c2 = self.c2.as_ref();
        #[cfg(not(feature = "alloc"))]
        let c2 = self.c2;

        let point = self.c1.to_sec1_point(false);
        let (x, y) = match point.coordinates() {
            Coordinates::Uncompressed { x, y } => (x, y),
            _ => unreachable!(),
        };
        UintRef::new(x)?.encode(writer)?;
        UintRef::new(y)?.encode(writer)?;
        OctetStringRef::new(&self.c3)?.encode(writer)?;

        OctetStringRef::new(c2)?.encode(writer)?;
        Ok(())
    }
}

#[cfg(feature = "der")]
impl<'a, C, D> DecodeValue<'a> for Cipher<'a, C, D>
where
    C: CurveArithmetic,
    D: OutputSizeUser,
    C::AffinePoint: FromSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
{
    type Error = der::Error;
    fn decode_value<R: Reader<'a>>(
        decoder: &mut R,
        header: der::Header,
    ) -> core::result::Result<Self, Self::Error> {
        decoder.read_nested(header.length(), |nr| {
            use elliptic_curve::sec1::Sec1Point;

            let x = UintRef::decode(nr)?.as_bytes();
            let y = UintRef::decode(nr)?.as_bytes();
            let digest = <&OctetStringRef>::decode(nr)?.as_bytes();

            if digest.len() != D::OutputSize::USIZE {
                return Err(Tag::OctetString.length_error().into());
            }
            let cipher = <&OctetStringRef>::decode(nr)?.as_bytes();

            let size = C::FieldBytesSize::USIZE;

            let num_zeroes = size
                .checked_sub(x.len())
                .ok_or_else(|| Tag::Integer.length_error())?;
            let mut x_arr = Array::default();
            x_arr[num_zeroes..].clone_from_slice(x);

            let num_zeroes = size
                .checked_sub(y.len())
                .ok_or_else(|| Tag::Integer.length_error())?;
            let mut y_arr = Array::default();
            y_arr[num_zeroes..].clone_from_slice(y);

            let point = Sec1Point::<C>::from_affine_coordinates(&x_arr, &y_arr, false);
            let c1: C::AffinePoint = Option::from(C::AffinePoint::from_sec1_point(&point))
                .ok_or_else(|| {
                    der::Error::new(
                        der::ErrorKind::Value { tag: Tag::Integer },
                        Length::new(C::FieldBytesSize::U32 * 2),
                    )
                })?;

            #[cfg(feature = "alloc")]
            let c2 = Cow::Borrowed(cipher);
            #[cfg(not(feature = "alloc"))]
            let c2 = cipher;

            let mut c3 = Output::<D>::default();
            c3.clone_from_slice(digest);

            Ok(Cipher { c1, c2, c3 })
        })
    }
}

/// Performs key derivation using a hash function and elliptic curve point.
fn kdf<D, C>(hasher: &mut D, kpb: C::AffinePoint, msg: &[u8], c2_out: &mut [u8]) -> Result<()>
where
    D: Update + FixedOutputReset,
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: ToSec1Point<C>,
{
    let digest_size = D::output_size();
    let mut ha = Output::<D>::default();
    let encode_point = kpb.to_sec1_point(false);
    let (x, y) = match encode_point.coordinates() {
        Coordinates::Uncompressed { x, y } => (x, y),
        _ => unreachable!(),
    };

    hasher.reset();

    msg.chunks(digest_size)
        .zip(c2_out.chunks_mut(digest_size))
        .map(|(input, output)| input.iter().zip(output))
        .enumerate()
        .try_for_each(|(index, iter)| {
            hasher.update(x);
            hasher.update(y);
            hasher.update(&(i32::try_from(index + 1).map_err(|_| Error)?).to_be_bytes());
            hasher.finalize_into_reset(&mut ha);

            iter.zip(&ha)
                .for_each(|((input, output), ha)| *output = input ^ ha);

            Ok(())
        })
}
