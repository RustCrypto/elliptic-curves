//! Taproot Schnorr signing key.

use super::{AUX_TAG, CHALLENGE_TAG, NONCE_TAG, Signature, VerifyingKey, tagged_hash};
use crate::{
    AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, SecretKey,
};
use elliptic_curve::{
    ops::Reduce,
    rand_core::{CryptoRng, TryCryptoRng},
    subtle::ConditionallySelectable,
    zeroize::{Zeroize, ZeroizeOnDrop},
};
use sha2::{Digest, Sha256};
use signature::{
    DigestSigner, Error, KeypairRef, MultipartSigner, RandomizedDigestSigner,
    RandomizedMultipartSigner, RandomizedSigner, Result, Signer,
    digest::{Update, consts::U32},
    hazmat::{PrehashSigner, RandomizedPrehashSigner},
};

#[cfg(feature = "serde")]
use serdect::serde::{Deserialize, Serialize, de, ser};

#[cfg(debug_assertions)]
use signature::hazmat::PrehashVerifier;

/// Taproot Schnorr signing key.
#[derive(Clone)]
pub struct SigningKey {
    /// Secret key material
    secret_key: NonZeroScalar,

    /// Verifying key
    verifying_key: VerifyingKey,
}

impl SigningKey {
    /// Generate a cryptographically random [`SigningKey`].
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        NonZeroScalar::random(rng).into()
    }

    /// Generate a cryptographically random [`SigningKey`].
    pub fn try_from_rng<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> core::result::Result<Self, R::Error> {
        Ok(NonZeroScalar::try_from_rng(rng)?.into())
    }

    /// Parse signing key from big endian-encoded bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        NonZeroScalar::try_from(bytes)
            .map(Into::into)
            .map_err(|_| Error::new())
    }

    /// Serialize as bytes.
    pub fn to_bytes(&self) -> FieldBytes {
        self.secret_key.to_bytes()
    }

    /// Get the [`VerifyingKey`] that corresponds to this signing key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Borrow the secret [`NonZeroScalar`] value for this key.
    ///
    /// # ⚠️ Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    pub fn as_nonzero_scalar(&self) -> &NonZeroScalar {
        &self.secret_key
    }

    /// Compute Schnorr signature.
    ///
    /// # ⚠️ Warning
    ///
    /// This is a low-level interface intended only for unusual use cases
    /// involving signing pre-hashed messages, or "raw" messages where the
    /// message is not hashed at all prior to being used to generate the
    /// Schnorr signature.
    ///
    /// The preferred interfaces are the [`Signer`] or [`RandomizedSigner`] traits.
    pub fn sign_raw(&self, msg: &[u8], aux_rand: &[u8; 32]) -> Result<Signature> {
        let mut t = tagged_hash(AUX_TAG).chain_update(aux_rand).finalize();

        for (a, b) in t.iter_mut().zip(self.secret_key.to_bytes().iter()) {
            *a ^= b
        }

        let rand = tagged_hash(NONCE_TAG)
            .chain_update(t)
            .chain_update(self.verifying_key.as_affine().x.to_bytes())
            .chain_update(msg)
            .finalize();

        let k = NonZeroScalar::try_from(&*rand)
            .map(Self::from)
            .map_err(|_| Error::new())?;

        let secret_key = k.secret_key;
        let verifying_point = AffinePoint::from(k.verifying_key);
        let r = verifying_point.x.normalize();

        let e = <Scalar as Reduce<FieldBytes>>::reduce(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r.to_bytes())
                .chain_update(self.verifying_key.to_bytes())
                .chain_update(msg)
                .finalize(),
        );

        let s = *secret_key + e * *self.secret_key;
        let s = Option::from(NonZeroScalar::new(s)).ok_or_else(Error::new)?;
        let sig = Signature { r, s };

        #[cfg(debug_assertions)]
        self.verifying_key.verify_prehash(msg, &sig)?;

        Ok(sig)
    }
}

impl From<NonZeroScalar> for SigningKey {
    #[inline]
    fn from(mut secret_key: NonZeroScalar) -> SigningKey {
        let odd = (ProjectivePoint::GENERATOR * *secret_key)
            .to_affine()
            .y
            .normalize()
            .is_odd();

        secret_key.conditional_assign(&-secret_key, odd);

        let verifying_key = VerifyingKey {
            inner: PublicKey::from_secret_scalar(&secret_key),
        };

        SigningKey {
            secret_key,
            verifying_key,
        }
    }
}

impl From<SecretKey> for SigningKey {
    #[inline]
    fn from(secret_key: SecretKey) -> SigningKey {
        SigningKey::from(&secret_key)
    }
}

impl From<&SecretKey> for SigningKey {
    fn from(secret_key: &SecretKey) -> SigningKey {
        secret_key.to_nonzero_scalar().into()
    }
}

//
// `*Signer` trait impls
//

impl<D> DigestSigner<D, Signature> for SigningKey
where
    D: Digest<OutputSize = U32> + Update,
{
    fn try_sign_digest<F: Fn(&mut D) -> Result<()>>(&self, f: F) -> Result<Signature> {
        let mut digest = D::new();
        f(&mut digest)?;
        self.sign_raw(&digest.finalize(), &Default::default())
    }
}

impl PrehashSigner<Signature> for SigningKey {
    fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature> {
        self.sign_raw(prehash, &Default::default())
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey
where
    D: Digest<OutputSize = U32> + Update,
{
    fn try_sign_digest_with_rng<R: TryCryptoRng + ?Sized, F: Fn(&mut D) -> Result<()>>(
        &self,
        rng: &mut R,
        f: F,
    ) -> Result<Signature> {
        let mut digest = D::new();
        f(&mut digest)?;

        let mut aux_rand = [0u8; 32];
        rng.try_fill_bytes(&mut aux_rand)
            .map_err(|_| Error::new())?;
        self.sign_raw(&digest.finalize(), &aux_rand)
    }
}

impl RandomizedSigner<Signature> for SigningKey {
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Signature> {
        self.try_multipart_sign_with_rng(rng, &[msg])
    }
}

impl RandomizedMultipartSigner<Signature> for SigningKey {
    fn try_multipart_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[&[u8]],
    ) -> Result<Signature> {
        self.try_sign_digest_with_rng(rng, |digest: &mut Sha256| {
            msg.iter().for_each(|&slice| Update::update(digest, slice));
            Ok(())
        })
    }
}

impl RandomizedPrehashSigner<Signature> for SigningKey {
    fn sign_prehash_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        prehash: &[u8],
    ) -> Result<Signature> {
        let mut aux_rand = [0u8; 32];
        rng.try_fill_bytes(&mut aux_rand)
            .map_err(|_| Error::new())?;

        self.sign_raw(prehash, &aux_rand)
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature> {
        self.try_multipart_sign(&[msg])
    }
}

impl MultipartSigner<Signature> for SigningKey {
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> Result<Signature> {
        self.try_sign_digest(|digest: &mut Sha256| {
            msg.iter().for_each(|&slice| Update::update(digest, slice));
            Ok(())
        })
    }
}

//
// Other trait impls
//

impl AsRef<VerifyingKey> for SigningKey {
    fn as_ref(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

impl KeypairRef for SigningKey {
    type VerifyingKey = VerifyingKey;
}

impl ZeroizeOnDrop for SigningKey {}

#[cfg(feature = "serde")]
impl Serialize for SigningKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.secret_key.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SigningKey {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(SigningKey::from(NonZeroScalar::deserialize(deserializer)?))
    }
}
