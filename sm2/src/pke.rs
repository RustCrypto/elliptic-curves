//! SM2 Encryption Algorithm (SM2) as defined in [draft-shen-sm2-ecdsa § 5].
//!
//! ## Usage
#![cfg_attr(feature = "alloc", doc = "```")]
#![cfg_attr(not(feature = "alloc"), doc = "```ignore")]
//! use sm2::pke::{EcDecrypt, EcEncrypt, Cipher, Mode};
//! use sm2::SecretKey;
//! use rand_core::OsRng;
//! // Encrypting
//! let secret_key = SecretKey::try_from_rng(&mut OsRng).unwrap(); // serialize with `::to_bytes()`
//! let public_key = secret_key.public_key();
//! let plaintext = b"plaintext";
//! let cipher = public_key.encrypt(plaintext).unwrap();
//! let ciphertext = cipher.to_vec(Mode::C1C3C2);
//!
//! // Decrypting
//! let cipher = Cipher::from_slice(&ciphertext, Mode::C1C3C2).unwrap();
//! let ciphertext = secret_key.decrypt(&cipher).unwrap();
//! assert_eq!(ciphertext, plaintext)
//!  ```
//!
//!
//!
//!

use core::cmp::min;

use elliptic_curve::{
    CurveArithmetic, Error, FieldBytesSize, Group, PrimeField, Result,
    array::typenum::Unsigned,
    ops::Reduce,
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, Tag, ToEncodedPoint},
};

use primeorder::{AffinePoint, PrimeCurveParams};
use signature::digest::{FixedOutputReset, Output, OutputSizeUser, Update};

#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, vec::Vec};

#[cfg(feature = "arithmetic")]
mod decrypting;
#[cfg(feature = "arithmetic")]
mod encrypting;
use crate::Sm2;
use sm3::Sm3;

#[cfg(feature = "arithmetic")]
pub use self::{decrypting::EcDecrypt, encrypting::EcEncrypt};

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
/// TODO: ASN1 Encode and Decode
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
    C: PrimeCurveParams,
    C::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
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
        let c1 = Option::from(C::AffinePoint::from_encoded_point(&encoded_c1)).ok_or(Error)?;
        // B2: compute point 𝑆 = [ℎ]𝐶1
        let scalar: C::Scalar = Reduce::<C::Uint>::reduce(C::Uint::from(C::FieldElement::S));
        let s: C::ProjectivePoint = c1 * scalar;
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

/// Performs key derivation using a hash function and elliptic curve point.     
/// Magic modification: Does it support streaming encryption and decryption?
fn kdf<D, C>(hasher: &mut D, kpb: AffinePoint<C>, msg: &[u8], c2_out: &mut [u8]) -> Result<()>
where
    D: Update + FixedOutputReset,
    C: CurveArithmetic + PrimeCurveParams,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: ToEncodedPoint<C>,
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
