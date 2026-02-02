use core::fmt::Debug;

use crate::{
    AffinePoint, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, UncompressedPoint,
    arithmetic::field::FieldElement,
    pke::{kdf, vec},
};

use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};
use elliptic_curve::{
    Error, Generate, Group, Result,
    bigint::{U256, Uint},
    ops::Reduce,
    pkcs8::der::Encode,
    rand_core::TryCryptoRng,
    sec1::ToSec1Point,
};

use primeorder::PrimeField;
use sm3::{
    Sm3,
    digest::{Digest, DynDigest},
};

use super::{Cipher, Mode};
/// Represents an encryption key used for encrypting messages using elliptic curve cryptography.
#[derive(Clone, Debug)]
pub struct EncryptingKey {
    public_key: PublicKey,
    mode: Mode,
}

impl EncryptingKey {
    /// Initialize [`EncryptingKey`] from PublicKey
    pub fn new(public_key: PublicKey) -> Self {
        Self::new_with_mode(public_key, Mode::C1C2C3)
    }

    /// Initialize [`EncryptingKey`] from PublicKey and set Encryption mode
    pub fn new_with_mode(public_key: PublicKey, mode: Mode) -> Self {
        Self { public_key, mode }
    }

    /// Initialize [`EncryptingKey`] from a SEC1-encoded public key.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        let public_key = PublicKey::from_sec1_bytes(bytes).map_err(|_| Error)?;
        Ok(Self::new(public_key))
    }

    /// Initialize [`EncryptingKey`] from an affine point.
    ///
    /// Returns an [`Error`] if the given affine point is the additive identity
    /// (a.k.a. point at infinity).
    pub fn from_affine(affine: AffinePoint) -> Result<Self> {
        let public_key = PublicKey::from_affine(affine).map_err(|_| Error)?;
        Ok(Self::new(public_key))
    }

    /// Borrow the inner [`AffinePoint`] for this public key.
    pub fn as_affine(&self) -> &AffinePoint {
        self.public_key.as_affine()
    }

    /// Convert this [`EncryptingKey`] into the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3
    /// (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    pub fn to_sec1_bytes(&self) -> Box<[u8]> {
        self.public_key.to_sec1_bytes()
    }

    /// Encrypts a message using the encryption key.
    ///
    /// This method calculates the digest using the `Sm3` hash function and then performs encryption.
    pub fn encrypt<R: TryCryptoRng + ?Sized>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_digest::<R, Sm3>(rng, msg)
    }

    /// Encrypts a message and returns the result in ASN.1 format.
    ///
    /// This method calculates the digest using the `Sm3` hash function and performs encryption,
    /// then encodes the result in ASN.1 format.
    pub fn encrypt_der<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        self.encrypt_der_digest::<R, Sm3>(rng, msg)
    }

    /// Encrypts a message using a specified digest algorithm.
    pub fn encrypt_digest<R: TryCryptoRng + ?Sized, D>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>>
    where
        D: 'static + Digest + DynDigest + Send + Sync,
    {
        let mut digest = D::new();
        encrypt(rng, &self.public_key, self.mode, &mut digest, msg)
    }

    /// Encrypts a message using a specified digest algorithm and returns the result in ASN.1 format.
    pub fn encrypt_der_digest<R: TryCryptoRng + ?Sized, D>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>>
    where
        D: 'static + Digest + DynDigest + Send + Sync,
    {
        let mut digest = D::new();
        let cipher = encrypt(rng, &self.public_key, self.mode, &mut digest, msg)?;
        let digest_size = digest.output_size();
        let (_, cipher) = cipher.split_at(1);
        let (x, cipher) = cipher.split_at(32);
        let (y, cipher) = cipher.split_at(32);
        let (digest, cipher) = match self.mode {
            Mode::C1C2C3 => {
                let (cipher, digest) = cipher.split_at(cipher.len() - digest_size);
                (digest, cipher)
            }
            Mode::C1C3C2 => cipher.split_at(digest_size),
        };
        Ok(Cipher {
            x: Uint::from_be_slice(x),
            y: Uint::from_be_slice(y),
            digest,
            cipher,
        }
        .to_der()
        .map_err(elliptic_curve::pkcs8::Error::from)?)
    }
}

impl From<PublicKey> for EncryptingKey {
    fn from(value: PublicKey) -> Self {
        Self::new(value)
    }
}

/// Encrypts a message using the specified public key, mode, and digest algorithm.
fn encrypt<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    public_key: &PublicKey,
    mode: Mode,
    digest: &mut dyn DynDigest,
    msg: &[u8],
) -> Result<Vec<u8>> {
    let mut c1 = [0; size_of::<UncompressedPoint>()];
    let mut c2 = msg.to_owned();
    let mut hpb: AffinePoint;
    loop {
        // A1: generate a random number 𝑘 ∈ [1, 𝑛 − 1] with the random number generator
        let k = NonZeroScalar::try_generate_from_rng(rng).map_err(|_| Error)?;

        // A2: compute point 𝐶1 = [𝑘]𝐺 = (𝑥1, 𝑦1)
        let kg = ProjectivePoint::mul_by_generator(&k).to_affine();

        // A3: compute point 𝑆 = [ℎ]𝑃𝐵 of the elliptic curve
        let pb_point = public_key.as_affine();
        let s = *pb_point * Scalar::reduce(&U256::from_u32(FieldElement::S));
        if s.is_identity().into() {
            return Err(Error);
        }

        // A4: compute point [𝑘]𝑃𝐵 = (𝑥2, 𝑦2)
        hpb = (s * *k).to_affine();

        // A5: compute 𝑡 = 𝐾𝐷𝐹(𝑥2||𝑦2, 𝑘𝑙𝑒𝑛)
        // A6: compute 𝐶2 = 𝑀 ⊕ t
        kdf(digest, hpb, &mut c2)?;

        // // If 𝑡 is an all-zero bit string, go to A1.
        // if all of t are 0, xor(c2) == c2
        if c2.iter().zip(msg).any(|(pre, cur)| pre != cur) {
            let uncompress_kg = kg.to_sec1_point(false);
            c1.copy_from_slice(uncompress_kg.as_bytes());
            break;
        }
    }
    let encode_point = hpb.to_sec1_point(false);

    // A7: compute 𝐶3 = 𝐻𝑎𝑠ℎ(𝑥2||𝑀||𝑦2)
    let mut c3 = vec![0; digest.output_size()];
    digest.update(encode_point.x().ok_or(Error)?);
    digest.update(msg);
    digest.update(encode_point.y().ok_or(Error)?);
    digest.finalize_into_reset(&mut c3).map_err(|_e| Error)?;

    // A8: output the ciphertext 𝐶 = 𝐶1||𝐶2||𝐶3.
    Ok(match mode {
        Mode::C1C2C3 => [c1.as_slice(), &c2, &c3].concat(),
        Mode::C1C3C2 => [c1.as_slice(), &c3, &c2].concat(),
    })
}
