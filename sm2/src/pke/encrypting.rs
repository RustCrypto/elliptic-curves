use core::fmt::Debug;

#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, boxed::Box, vec};

use crate::PublicKey;
use crate::Sm2;

use super::kdf;

use rand_core::TryCryptoRng;

use elliptic_curve::{
    CurveArithmetic, CurveGroup, Error, Group, NonZeroScalar, Result,
    ops::Reduce,
    sec1::{ModulusSize, ToEncodedPoint},
};

use primeorder::PrimeField;
use sm3::{
    Sm3,
    digest::{Digest, FixedOutputReset, Output, Update},
};

use super::Cipher;
/// Represents an encryption key used for encrypting messages using elliptic curve cryptography.
#[derive(Clone, Debug)]
pub struct EncryptingKey {
    public_key: PublicKey,
}

impl EncryptingKey {
    /// Initialize [`EncryptingKey`] from PublicKey
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
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
    pub fn from_affine(affine: crate::AffinePoint) -> Result<Self> {
        let public_key = PublicKey::from_affine(affine).map_err(|_| Error)?;
        Ok(Self::new(public_key))
    }

    /// Borrow the inner [`crate::AffinePoint`] for this public key.
    pub fn as_affine(&self) -> &crate::AffinePoint {
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

    /// Encrypt into [`Cipher`] using the default digest algorithm [`Sm3`].
    #[cfg(all(feature = "getrandom", feature = "alloc"))]
    pub fn encrypt<'a>(&self, msg: &[u8]) -> Result<Cipher<'a, Sm2, Sm3>> {
        use rand_core::OsRng;
        self.encrypt_rng(&mut OsRng, msg)
    }

    /// Encrypt into [`Cipher`] using the default digest algorithm [`Sm3`].
    /// Use a custom RNG.
    #[cfg(feature = "alloc")]
    pub fn encrypt_rng<'a, R: TryCryptoRng>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Cipher<'a, Sm2, Sm3>> {
        self.encrypt_digest_rng::<_, Sm3>(rng, msg)
    }

    /// Encrypt into [`Cipher`] using the specified digest algorithm.   
    /// Use a custom RNG.
    #[cfg(feature = "alloc")]
    pub fn encrypt_digest_rng<'a, R: TryCryptoRng, D: Digest + FixedOutputReset>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Cipher<'a, Sm2, D>> {
        let mut c1 = <Sm2 as CurveArithmetic>::AffinePoint::default();
        let mut c2 = vec![0; msg.len()];
        let mut c3 = Output::<D>::default();
        self.encrypt_digest_rng_into::<R, D>(rng, msg, &mut c1, &mut c2, &mut c3)?;
        Ok(Cipher {
            c1,
            c2: c2.into(),
            c3,
        })
    }

    /// Encrypt into [`Cipher`] using the default digest algorithm [`Sm3`].
    /// `c2_out_buf` is the output of c2.   
    /// Use a custom RNG.
    pub fn encrypt_buf_rng<'a, R: TryCryptoRng>(
        &self,
        rng: &mut R,
        msg: &[u8],
        c2_out_buf: &'a mut [u8],
    ) -> Result<Cipher<'a, Sm2, Sm3>> {
        self.encrypt_buf_digest_rng::<R, Sm3>(rng, msg, c2_out_buf)
    }

    /// Encrypt into [`Cipher`] using the specified digest algorithm.
    /// `c2_out_buf` is the output of c2.
    /// Use a custom RNG.
    pub fn encrypt_buf_digest_rng<'a, R: TryCryptoRng, D: Digest + FixedOutputReset>(
        &self,
        rng: &mut R,
        msg: &[u8],
        c2_out_buf: &'a mut [u8],
    ) -> Result<Cipher<'a, Sm2, D>> {
        let mut c1 = <Sm2 as CurveArithmetic>::AffinePoint::default();
        let mut c3 = Output::<D>::default();
        let len = self.encrypt_digest_rng_into::<R, D>(rng, msg, &mut c1, c2_out_buf, &mut c3)?;
        let c2 = &c2_out_buf[..len];

        #[cfg(feature = "alloc")]
        let c2 = Cow::Borrowed(c2);

        Ok(Cipher { c1, c2, c3 })
    }

    /// Encrypt into the specified buffer using the specified digest algorithm.
    /// * Note: buffer zones are prohibited from overlapping
    /// * returns c2_out length
    pub fn encrypt_digest_rng_into<R: TryCryptoRng, D: Digest + FixedOutputReset>(
        &self,
        rng: &mut R,
        msg: &[u8],
        c1_out: &mut <Sm2 as CurveArithmetic>::AffinePoint,
        c2_out: &mut [u8],
        c3_out: &mut Output<D>,
    ) -> Result<usize> {
        encrypt_into::<Sm2, R, D>(
            self.public_key.as_affine(),
            rng,
            msg,
            c1_out,
            c2_out,
            c3_out,
        )
    }
}

impl From<PublicKey> for EncryptingKey {
    fn from(value: PublicKey) -> Self {
        Self::new(value)
    }
}

fn encrypt_into<C, R, D>(
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
    C::AffinePoint: ToEncodedPoint<C>,
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
        let k: C::Scalar = C::Scalar::from(NonZeroScalar::try_from_rng(rng).map_err(|_e| Error)?);

        // A2: compute point 𝐶1 = [𝑘]𝐺 = (𝑥1, 𝑦1)
        let kg: C::AffinePoint = C::ProjectivePoint::mul_by_generator(&k).into();

        // A3: compute point 𝑆 = [ℎ]𝑃𝐵 of the elliptic curve
        let scalar: C::Scalar = Reduce::<C::Uint>::reduce(C::Uint::from(C::Scalar::S));
        let s: C::ProjectivePoint = C::ProjectivePoint::from(*affine_point) * scalar;
        if s.is_identity().into() {
            return Err(Error);
        }

        // A4: compute point [𝑘]𝑃𝐵 = (𝑥2, 𝑦2)
        hpb = (s * k).to_affine();

        // A5: compute 𝑡 = 𝐾𝐷𝐹(𝑥2||𝑦2, 𝑘𝑙𝑒𝑛)
        // A6: compute 𝐶2 = 𝑀 ⊕ t
        kdf::<D, C>(&mut digest, hpb, msg, c2_out)?;

        // // If 𝑡 is an all-zero bit string, go to A1.
        // if all of t are 0, xor(c2) == c2
        if c2_out.iter().zip(msg).any(|(pre, cur)| pre != cur) {
            *c1_out = kg;
            break;
        }
    }
    let encode_point = hpb.to_encoded_point(false);

    // A7: compute 𝐶3 = 𝐻𝑎𝑠ℎ(𝑥2||𝑀||𝑦2)
    Digest::reset(&mut digest);
    Digest::update(&mut digest, encode_point.x().ok_or(Error)?);
    Digest::update(&mut digest, msg);
    Digest::update(&mut digest, encode_point.y().ok_or(Error)?);
    Digest::finalize_into_reset(&mut digest, c3_out);

    Ok(c2_out.len())
}
