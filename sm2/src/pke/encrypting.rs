use crate::{AffinePoint, PublicKey};
#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, boxed::Box, vec, vec::Vec};
use core::fmt::Debug;
#[cfg(feature = "alloc")]
use elliptic_curve::pkcs8::der::Encode;
use elliptic_curve::{
    CurveArithmetic, CurveGroup, Error, Generate, Group, NonZeroScalar, PrimeField, Result,
    ops::Reduce,
    rand_core::TryCryptoRng,
    sec1::{Coordinates, ModulusSize, ToSec1Point},
};
use sm3::digest::{Digest, FixedOutputReset, Output, Update};

use super::{Cipher, Mode};
/// Represents an encryption key used for encrypting messages using elliptic curve cryptography.
#[derive(Clone, Debug)]
pub struct EncryptingKey {
    public_key: PublicKey,
    mode: Mode,
}

impl EncryptingKey {
    /// Initialize [`EncryptingKey`] from PublicKey with the default encryption mode (`C1C3C2`).
    pub fn new(public_key: PublicKey) -> Self {
        Self::new_with_mode(public_key, Default::default())
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
    #[cfg(feature = "alloc")]
    pub fn to_sec1_bytes(&self) -> Box<[u8]> {
        self.public_key.to_sec1_bytes()
    }

    /// Encrypts a message using the encryption key.
    ///
    /// This method calculates the digest using the `Sm3` hash function and then performs encryption.
    #[cfg(feature = "alloc")]
    pub fn encrypt<R: TryCryptoRng>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_digest::<R, sm3::Sm3>(rng, msg)
    }

    /// Encrypts a message and returns the result in ASN.1 format.
    ///
    /// This method calculates the digest using the `Sm3` hash function and performs encryption,
    /// then encodes the result in ASN.1 format.
    #[cfg(feature = "alloc")]
    pub fn encrypt_der<R: TryCryptoRng>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_der_digest::<R, sm3::Sm3>(rng, msg)
    }

    /// Encrypts a message using a specified digest algorithm.
    #[cfg(feature = "alloc")]
    pub fn encrypt_digest<R: TryCryptoRng, D>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>>
    where
        D: Digest + FixedOutputReset,
    {
        let cipher = self.encrypt_cipher::<R, D>(rng, msg)?;
        Ok(cipher.to_vec(self.mode, true))
    }

    /// Encrypts a message using a specified digest algorithm and returns the result in ASN.1 format.
    #[cfg(feature = "alloc")]
    pub fn encrypt_der_digest<R: TryCryptoRng, D>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>>
    where
        D: Digest + FixedOutputReset,
    {
        let cipher = self.encrypt_cipher::<R, D>(rng, msg)?;

        Ok(cipher
            .to_der()
            .map_err(elliptic_curve::pkcs8::Error::from)?)
    }

    /// Encrypts a message using a specified digest algorithm and returns a Cipher object.
    #[cfg(feature = "alloc")]
    pub fn encrypt_cipher<R, D>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Cipher<'static, crate::Sm2, D>>
    where
        D: Digest + FixedOutputReset,
        R: TryCryptoRng,
    {
        use alloc::borrow::Cow;

        let mut c2_buf = vec![0; msg.len()];
        let Cipher { c1, c2: _, c3 } =
            self.encrypt_cipher_with_buf::<R, D>(rng, msg, &mut c2_buf)?;

        Ok(Cipher {
            c1,
            c2: Cow::Owned(c2_buf),
            c3,
        })
    }

    /// Encrypts a message using a specified digest algorithm,
    /// storing the ciphertext in the provided buffer and returning a `Cipher` that references the buffer.
    pub fn encrypt_cipher_with_buf<'a, R, D>(
        &self,
        rng: &mut R,
        msg: &[u8],
        buf: &'a mut [u8],
    ) -> Result<Cipher<'a, crate::Sm2, D>>
    where
        D: Digest + FixedOutputReset,
        R: TryCryptoRng,
    {
        if buf.len() < msg.len() {
            return Err(Error);
        }

        let mut c1 = AffinePoint::default();
        let mut c3 = Output::<D>::default();
        let size = encrypt::<crate::Sm2, R, D>(self.as_affine(), rng, msg, &mut c1, buf, &mut c3)?;

        #[cfg(feature = "alloc")]
        let c2 = Cow::Borrowed(&buf[..size]);
        #[cfg(not(feature = "alloc"))]
        let c2 = &buf[..size];

        Ok(Cipher { c1, c2, c3 })
    }
}

impl From<PublicKey> for EncryptingKey {
    fn from(value: PublicKey) -> Self {
        Self::new(value)
    }
}

/// Encrypts a message using the specified public key, mode, and digest algorithm.
fn encrypt<C, R, D>(
    affine_point: &C::AffinePoint,
    rng: &mut R,
    msg: &[u8],
    c1_out: &mut C::AffinePoint,
    c2_out: &mut [u8],
    c3_out: &mut Output<D>,
) -> Result<usize>
where
    C: CurveArithmetic,
    R: TryCryptoRng,
    D: FixedOutputReset + Digest + Update,
    C::AffinePoint: ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
{
    if c2_out.len() < msg.len() {
        return Err(Error);
    }
    let c2_out = &mut c2_out[..msg.len()];

    let mut digest = D::new();
    let mut hpb: C::AffinePoint;
    loop {
        // A1: generate a random number 𝑘 ∈ [1, 𝑛 − 1] with the random number generator
        let k = NonZeroScalar::<C>::try_generate_from_rng(rng).map_err(|_| Error)?;

        // A2: compute point 𝐶1 = [𝑘]𝐺 = (𝑥1, 𝑦1)
        let kg: C::AffinePoint = C::ProjectivePoint::mul_by_generator(&k).into();

        // A3: compute point 𝑆 = [ℎ]𝑃𝐵 of the elliptic curve
        let scalar: C::Scalar = Reduce::<C::Uint>::reduce(&C::Uint::from(C::Scalar::S));
        let s: C::ProjectivePoint = C::ProjectivePoint::from(*affine_point) * scalar;
        if s.is_identity().into() {
            return Err(Error);
        }

        // A4: compute point [𝑘]𝑃𝐵 = (𝑥2, 𝑦2)
        hpb = (s * *k).to_affine();

        // A5: compute 𝑡 = 𝐾𝐷𝐹(𝑥2||𝑦2, 𝑘𝑙𝑒𝑛)
        // A6: compute 𝐶2 = 𝑀 ⊕ t
        crate::pke::kdf::<D, C>(&mut digest, hpb, msg, c2_out)?;

        // // If 𝑡 is an all-zero bit string, go to A1.
        // if all of t are 0, xor(c2) == c2
        if c2_out.iter().zip(msg).any(|(pre, cur)| pre != cur) {
            *c1_out = kg;
            break;
        }
    }
    let encode_point = hpb.to_sec1_point(false);
    let (x, y) = match encode_point.coordinates() {
        Coordinates::Uncompressed { x, y } => (x, y),
        _ => unreachable!(),
    };

    // A7: compute 𝐶3 = 𝐻𝑎𝑠ℎ(𝑥2||𝑀||𝑦2)
    Digest::reset(&mut digest);
    Digest::update(&mut digest, x);
    Digest::update(&mut digest, msg);
    Digest::update(&mut digest, y);
    Digest::finalize_into_reset(&mut digest, c3_out);

    Ok(c2_out.len())
}
