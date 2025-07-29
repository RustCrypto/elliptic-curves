//! SM2 Encryption Algorithm (SM2) as defined in [draft-shen-sm2-ecdsa § 5].
//!
//! ## Usage
//!
//! NOTE: requires the `sm3` crate for digest functions and the `primeorder` crate for prime field operations.
//!
//! The `DecryptingKey` struct is used for decrypting messages that were encrypted using the SM2 encryption algorithm.
//! It is initialized with a `SecretKey` or a non-zero scalar value and can decrypt ciphertexts using the specified decryption mode.
#![cfg_attr(feature = "std", doc = "```")]
#![cfg_attr(not(feature = "std"), doc = "```ignore")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use rand_core::OsRng; // requires 'os_rng` feature
//! use sm2::{
//!     pke::{EncryptingKey, Mode, Cipher},
//!     {SecretKey, PublicKey},
//!     pkcs8::der::{Encode, Decode}
//! };
//!
//! // Encrypting
//! let secret_key = SecretKey::try_from_rng(&mut OsRng).unwrap(); // serialize with `::to_bytes()`
//! let public_key = secret_key.public_key();
//! let encrypting_key = EncryptingKey::new(public_key);
//! let plaintext = b"plaintext";
//! let cipher = encrypting_key.encrypt_rng(&mut OsRng, plaintext)?;
//! let ciphertext = cipher.to_vec(Mode::C1C2C3);
//!
//! use sm2::pke::DecryptingKey;
//! // Decrypting
//! let cipher = Cipher::from_slice(&ciphertext, Mode::C1C2C3)?;
//! let decrypting_key = DecryptingKey::from_nonzero_scalar(secret_key.to_nonzero_scalar());
//! assert_eq!(decrypting_key.decrypt(&cipher)?, plaintext);
//!
//! // Encrypting ASN.1 DER
//!
//! let cipher = encrypting_key.encrypt_rng(&mut OsRng, plaintext)?;
//! let ciphertext = cipher.to_der()?;
//! // Decrypting ASN.1 DER
//! let cipher = Cipher::from_der(&ciphertext)?;
//! assert_eq!(decrypting_key.decrypt(&cipher)?, plaintext);
//!
//! Ok(())
//! # }
//!  ```
//!
//!
//!

use core::cmp::min;

#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, vec::Vec};

use elliptic_curve::{
    CurveArithmetic, Error, Group, PrimeField, Result,
    array::Array,
    ops::Reduce,
    pkcs8::der::{
        self, Decode, DecodeValue, Encode, EncodeValue, Length, Reader, Sequence, Writer,
        asn1::{OctetStringRef, UintRef},
    },
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, Tag, ToEncodedPoint},
};

use crate::Sm2;
use sm3::Sm3;
use sm3::digest::{FixedOutputReset, Output, OutputSizeUser, Update, typenum::Unsigned};

#[cfg(feature = "arithmetic")]
mod decrypting;
#[cfg(feature = "arithmetic")]
mod encrypting;

#[cfg(feature = "arithmetic")]
pub use self::{decrypting::DecryptingKey, encrypting::EncryptingKey};

/// Modes for the cipher encoding/decoding.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// old mode
    C1C2C3,
    /// new mode
    C1C3C2,
}
impl Default for Mode {
    fn default() -> Self {
        Self::C1C3C2
    }
}
/// Represents a cipher structure containing encryption-related data (asn.1 format).
///
/// The `Cipher` structure includes the coordinates of the elliptic curve point (`x`, `y`),
/// the digest of the message, and the encrypted cipher text.
#[derive(Debug)]
pub struct Cipher<'a, C: CurveArithmetic = Sm2, D: OutputSizeUser = Sm3> {
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
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
    D: OutputSizeUser,
{
    /// Decode from slice
    pub fn from_slice(cipher: &'a [u8], mode: Mode) -> Result<Self> {
        let tag = Tag::from_u8(cipher.first().cloned().ok_or(Error)?)?;
        let c1_len = tag.message_len(C::FieldBytesSize::USIZE);

        // B1: get 𝐶1 from 𝐶
        let (c1, c) = cipher.split_at(c1_len);
        // verify that point c1 satisfies the elliptic curve
        let encoded_c1 = EncodedPoint::<C>::from_bytes(c1)?;
        let c1: C::AffinePoint =
            Option::from(FromEncodedPoint::from_encoded_point(&encoded_c1)).ok_or(Error)?;
        // B2: compute point 𝑆 = [ℎ]𝐶1
        let scalar: C::Scalar = Reduce::<C::Uint>::reduce(C::Uint::from(C::Scalar::S));

        let s: C::ProjectivePoint = C::ProjectivePoint::from(c1) * scalar;
        if s.is_identity().into() {
            return Err(Error);
        }

        let digest_size = D::output_size();
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

    /// Encode to Vec
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self, mode: Mode) -> Vec<u8> {
        let point = self.c1.to_encoded_point(false);
        let len = point.len() + self.c2.len() + self.c3.len();
        let mut result = Vec::with_capacity(len);
        match mode {
            Mode::C1C2C3 => {
                result.extend(point.as_ref());
                result.extend(self.c2.as_ref());
                result.extend(&self.c3);
            }
            Mode::C1C3C2 => {
                result.extend(point.as_ref());
                result.extend(&self.c3);
                result.extend(self.c2.as_ref());
            }
        }

        result
    }
    /// Encode to Vec
    #[cfg(feature = "alloc")]
    pub fn to_vec_compressed(&self, mode: Mode) -> Vec<u8> {
        let point = self.c1.to_encoded_point(true);
        let len = point.len() + self.c2.len() + self.c3.len();
        let mut result = Vec::with_capacity(len);
        match mode {
            Mode::C1C2C3 => {
                result.extend(point.as_ref());
                result.extend(self.c2.as_ref());
                result.extend(&self.c3);
            }
            Mode::C1C3C2 => {
                result.extend(point.as_ref());
                result.extend(&self.c3);
                result.extend(self.c2.as_ref());
            }
        }

        result
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

impl<'a, C, D> Sequence<'a> for Cipher<'a, C, D>
where
    C: CurveArithmetic,
    D: OutputSizeUser,
    C::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
{
}

#[cfg_attr(not(feature = "alloc"), allow(clippy::useless_asref))]
impl<C, D> EncodeValue for Cipher<'_, C, D>
where
    C: CurveArithmetic,
    D: OutputSizeUser,
    C::AffinePoint: ToEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
{
    fn value_len(&self) -> der::Result<Length> {
        let point = self.c1.to_encoded_point(false);
        UintRef::new(point.x().expect("x is None"))?.encoded_len()?
            + UintRef::new(point.y().expect("y is None"))?.encoded_len()?
            + OctetStringRef::new(&self.c3)?.encoded_len()?
            + OctetStringRef::new(self.c2.as_ref())?.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        let point = self.c1.to_encoded_point(false);
        UintRef::new(point.x().expect("x is None"))?.encode(writer)?;
        UintRef::new(point.y().expect("y is None"))?.encode(writer)?;
        OctetStringRef::new(&self.c3)?.encode(writer)?;
        OctetStringRef::new(self.c2.as_ref())?.encode(writer)?;
        Ok(())
    }
}

impl<'a, C, D> DecodeValue<'a> for Cipher<'a, C, D>
where
    C: CurveArithmetic,
    D: OutputSizeUser,
    C::AffinePoint: FromEncodedPoint<C>,
    C::FieldBytesSize: ModulusSize,
{
    type Error = der::Error;
    fn decode_value<R: Reader<'a>>(
        decoder: &mut R,
        header: der::Header,
    ) -> core::result::Result<Self, der::Error> {
        decoder.read_nested(header.length, |nr| {
            let x = UintRef::decode(nr)?.as_bytes();
            let y = UintRef::decode(nr)?.as_bytes();
            let digest = OctetStringRef::decode(nr)?.as_bytes();
            let cipher = OctetStringRef::decode(nr)?.as_bytes();
            let size = C::FieldBytesSize::USIZE;

            let num_zeroes = size
                .checked_sub(x.len())
                .ok_or_else(|| der::Tag::Integer.length_error())?;
            let mut x_arr = Array::default();
            x_arr[num_zeroes..].clone_from_slice(x);

            let num_zeroes = size
                .checked_sub(y.len())
                .ok_or_else(|| der::Tag::Integer.length_error())?;
            let mut y_arr = Array::default();
            y_arr[num_zeroes..].clone_from_slice(y);

            let point = EncodedPoint::<C>::from_affine_coordinates(&x_arr, &y_arr, false);
            let c1 = Option::from(C::AffinePoint::from_encoded_point(&point)).ok_or_else(|| {
                der::Error::new(
                    der::ErrorKind::Value {
                        tag: der::Tag::Integer,
                    },
                    Length::new(C::FieldBytesSize::U32 * 2),
                )
            })?;

            #[cfg(feature = "alloc")]
            let c2 = Cow::Borrowed(cipher);
            #[cfg(not(feature = "alloc"))]
            let c2 = cipher;
            // Output::<D>::try_from()
            let c3 = Output::<D>::try_from(digest).map_err(|_e| {
                der::Error::new(
                    der::ErrorKind::Value {
                        tag: der::Tag::OctetString,
                    },
                    Length::new(D::output_size().try_into().expect("usize case error")),
                )
            })?;
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
    C::AffinePoint: ToEncodedPoint<C>,
{
    let klen = msg.len();
    let mut ct: i32 = 0x00000001;
    let mut offset = 0;
    let digest_size = D::output_size();
    let mut ha = Output::<D>::default();
    let encode_point = kpb.to_encoded_point(false);

    hasher.reset();
    while offset < klen {
        hasher.update(encode_point.x().ok_or(Error)?);
        hasher.update(encode_point.y().ok_or(Error)?);
        hasher.update(&ct.to_be_bytes());

        hasher.finalize_into_reset(&mut ha);

        let xor_len = min(digest_size, klen - offset);
        xor(msg, c2_out, &ha, offset, xor_len);
        offset += xor_len;
        ct += 1;
    }
    Ok(())
}

/// XORs a portion of the buffer `c2` with a hash value.
fn xor(msg: &[u8], c2_out: &mut [u8], ha: &[u8], offset: usize, xor_len: usize) {
    for i in 0..xor_len {
        c2_out[offset + i] = msg[offset + i] ^ ha[i];
    }
}
