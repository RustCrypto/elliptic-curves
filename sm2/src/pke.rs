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
//! use rand_core::OsRng; // requires 'getrandom` feature
//! use sm2::{
//!     pke::{EncryptingKey, Mode},
//!     {SecretKey, PublicKey}
//!
//! };
//!
//! // Encrypting
//! let secret_key = SecretKey::random(&mut OsRng); // serialize with `::to_bytes()`
//! let public_key = secret_key.public_key();
//! let encrypting_key = EncryptingKey::new_with_mode(public_key, Mode::C1C2C3);
//! let plaintext = b"plaintext";
//! let ciphertext = encrypting_key.encrypt(plaintext)?;
//!
//! use sm2::pke::DecryptingKey;
//! // Decrypting
//! let decrypting_key = DecryptingKey::new_with_mode(secret_key.to_nonzero_scalar(), Mode::C1C2C3);
//! assert_eq!(decrypting_key.decrypt(&ciphertext)?, plaintext);
//!
//! // Encrypting ASN.1 DER
//! let ciphertext = encrypting_key.encrypt_der(plaintext)?;
//!
//! // Decrypting ASN.1 DER
//! assert_eq!(decrypting_key.decrypt_der(&ciphertext)?, plaintext);
//!
//! Ok(())
//! # }
//!  ```
//!
//!
//!

use core::cmp::min;

use crate::AffinePoint;

#[cfg(feature = "alloc")]
use alloc::vec;

use elliptic_curve::{
    bigint::{Encoding, Uint, U256},
    pkcs8::der::{
        asn1::UintRef, Decode, DecodeValue, Encode, Length, Reader, Sequence, Tag, Writer,
    },
};

use elliptic_curve::{
    pkcs8::der::{asn1::OctetStringRef, EncodeValue},
    sec1::ToEncodedPoint,
    Result,
};
use sm3::digest::DynDigest;

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
/// Represents a cipher structure containing encryption-related data (asn.1 format).
///
/// The `Cipher` structure includes the coordinates of the elliptic curve point (`x`, `y`),
/// the digest of the message, and the encrypted cipher text.
pub struct Cipher<'a> {
    x: U256,
    y: U256,
    digest: &'a [u8],
    cipher: &'a [u8],
}

impl<'a> Sequence<'a> for Cipher<'a> {}

impl<'a> EncodeValue for Cipher<'a> {
    fn value_len(&self) -> elliptic_curve::pkcs8::der::Result<Length> {
        UintRef::new(&self.x.to_be_bytes())?.encoded_len()?
            + UintRef::new(&self.y.to_be_bytes())?.encoded_len()?
            + OctetStringRef::new(self.digest)?.encoded_len()?
            + OctetStringRef::new(self.cipher)?.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> elliptic_curve::pkcs8::der::Result<()> {
        UintRef::new(&self.x.to_be_bytes())?.encode(writer)?;
        UintRef::new(&self.y.to_be_bytes())?.encode(writer)?;
        OctetStringRef::new(self.digest)?.encode(writer)?;
        OctetStringRef::new(self.cipher)?.encode(writer)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for Cipher<'a> {
    type Error = elliptic_curve::pkcs8::der::Error;

    fn decode_value<R: Reader<'a>>(
        decoder: &mut R,
        header: elliptic_curve::pkcs8::der::Header,
    ) -> core::result::Result<Self, Self::Error> {
        decoder.read_nested(header.length, |nr| {
            let x = UintRef::decode(nr)?.as_bytes();
            let y = UintRef::decode(nr)?.as_bytes();
            let digest = OctetStringRef::decode(nr)?.into();
            let cipher = OctetStringRef::decode(nr)?.into();
            Ok(Cipher {
                x: Uint::from_be_bytes(zero_pad_byte_slice(x)?),
                y: Uint::from_be_bytes(zero_pad_byte_slice(y)?),
                digest,
                cipher,
            })
        })
    }
}

/// Performs key derivation using a hash function and elliptic curve point.
fn kdf(hasher: &mut dyn DynDigest, kpb: AffinePoint, c2: &mut [u8]) -> Result<()> {
    let klen = c2.len();
    let mut ct: i32 = 0x00000001;
    let mut offset = 0;
    let digest_size = hasher.output_size();
    let mut ha = vec![0u8; digest_size];
    let encode_point = kpb.to_encoded_point(false);

    while offset < klen {
        hasher.update(encode_point.x().ok_or(elliptic_curve::Error)?);
        hasher.update(encode_point.y().ok_or(elliptic_curve::Error)?);
        hasher.update(&ct.to_be_bytes());

        hasher
            .finalize_into_reset(&mut ha)
            .map_err(|_e| elliptic_curve::Error)?;

        let xor_len = min(digest_size, klen - offset);
        xor(c2, &ha, offset, xor_len);
        offset += xor_len;
        ct += 1;
    }
    Ok(())
}

/// XORs a portion of the buffer `c2` with a hash value.
fn xor(c2: &mut [u8], ha: &[u8], offset: usize, xor_len: usize) {
    for i in 0..xor_len {
        c2[offset + i] ^= ha[i];
    }
}

/// Converts a byte slice to a fixed-size array, padding with leading zeroes if necessary.
pub(crate) fn zero_pad_byte_slice<const N: usize>(
    bytes: &[u8],
) -> elliptic_curve::pkcs8::der::Result<[u8; N]> {
    let num_zeroes = N
        .checked_sub(bytes.len())
        .ok_or_else(|| Tag::Integer.length_error())?;

    // Copy input into `N`-sized output buffer with leading zeroes
    let mut output = [0u8; N];
    output[num_zeroes..].copy_from_slice(bytes);
    Ok(output)
}
