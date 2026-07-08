//! Taproot Schnorr signing key.

use super::{AUX_TAG, CHALLENGE_TAG, NONCE_TAG, Signature, VerifyingKey, tagged_hash};
use crate::{
    AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, SecretKey,
};
use core::fmt;
use elliptic_curve::{
    Generate,
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

/// Number of bytes of auxiliary randomness.
const AUX_RAND_BYTES: usize = 32;

/// Taproot Schnorr signing key.
#[derive(Clone)]
pub struct SigningKey {
    /// Secret key material
    secret_key: NonZeroScalar,

    /// Verifying key
    verifying_key: VerifyingKey,
}

impl SigningKey {
    /// Parse signing key from big endian-encoded bytes.
    ///
    /// # Errors
    /// Returns [`Error`] in the event the provided bytes overflow the curve order `n`.
    pub fn from_bytes(bytes: &FieldBytes) -> Result<Self> {
        NonZeroScalar::from_repr(*bytes)
            .into_option()
            .map(Into::into)
            .ok_or_else(Error::new)
    }

    /// Parse signing key from big endian-encoded byte slice.
    ///
    /// # Errors
    /// Returns [`Error`] if `bytes` is not 32-bytes long, or if it overflows the curve order `n`.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let x_bytes = FieldBytes::try_from(bytes).map_err(|_| Error::new())?;
        Self::from_bytes(&x_bytes)
    }

    /// Serialize as bytes.
    #[must_use]
    pub fn to_bytes(&self) -> FieldBytes {
        self.secret_key.to_bytes()
    }

    /// Get the [`VerifyingKey`] that corresponds to this signing key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Borrow the secret [`NonZeroScalar`] value for this key.
    ///
    /// <div class="warning">
    /// <b>Security Warning<b>
    ///
    /// This value is key material. Please treat it with the care it deserves!
    /// </div>
    #[must_use]
    pub fn as_nonzero_scalar(&self) -> &NonZeroScalar {
        &self.secret_key
    }

    /// Compute Schnorr signature.
    ///
    /// This is a low-level interface intended only for use cases that need to explicitly pass
    /// `aux_rand` rather than deriving it from an RNG.
    ///
    /// Prefer higher-level APIs like `Signer`, `RandomizedSigner`, or `(Randomized)PrehashSigner`
    /// instead whenever possible.
    ///
    /// # Errors
    /// Returns an error if the generated signature would be invalid (i.e. if derived `k` were `0`).
    #[doc(hidden)]
    pub fn sign_raw(&self, msg: &[u8], aux_rand: &[u8; AUX_RAND_BYTES]) -> Result<Signature> {
        let mut t = tagged_hash(AUX_TAG).chain_update(aux_rand).finalize();

        for (a, b) in t.iter_mut().zip(self.secret_key.to_bytes().iter()) {
            *a ^= b;
        }

        let rand = tagged_hash(NONCE_TAG)
            .chain_update(t)
            .chain_update(self.verifying_key.as_affine().x.to_bytes())
            .chain_update(msg)
            .finalize();

        let mut k = NonZeroScalar::new(Scalar::reduce(&rand))
            .into_option()
            .ok_or_else(Error::new)?;

        // Compute R = k*G using precomputed tables, convert to affine once, and ensure R has an
        // even y-coordinate (BIP340 requirement).
        let R = ProjectivePoint::mul_by_generator(&k).to_affine();
        let odd = R.y.normalize().is_odd();
        k.conditional_assign(&-k, odd);
        let r = R.x.normalize();

        let e = Scalar::reduce(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r.to_bytes())
                .chain_update(self.verifying_key.to_bytes())
                .chain_update(msg)
                .finalize(),
        );

        let s = *k + e * *self.secret_key;
        let s = NonZeroScalar::new(s).into_option().ok_or_else(Error::new)?;
        let sig = Signature { r, s };

        #[cfg(debug_assertions)]
        self.verifying_key.verify_prehash(msg, &sig)?;

        Ok(sig)
    }

    /// Deprecated: Generate a cryptographically random [`SigningKey`].
    #[deprecated(since = "0.14.0", note = "use the `Generate` trait instead")]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::generate_from_rng(rng)
    }
}

impl From<NonZeroScalar> for SigningKey {
    #[inline]
    fn from(mut secret_key: NonZeroScalar) -> SigningKey {
        // Compute the public key point once using precomputed generator tables,
        // then conditionally negate to ensure even y.
        let point = ProjectivePoint::mul_by_generator(&secret_key).to_affine();
        let odd = point.y.normalize().is_odd();

        secret_key.conditional_assign(&-secret_key, odd);
        let neg_point = -point;
        let correct_point = AffinePoint::conditional_select(&point, &neg_point, odd);

        let verifying_key = VerifyingKey {
            inner: PublicKey::from_affine(correct_point)
                .unwrap_or_else(|_| PublicKey::from_secret_scalar(&secret_key)),
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

impl Generate for SigningKey {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> core::result::Result<Self, R::Error> {
        Ok(NonZeroScalar::try_generate_from_rng(rng)?.into())
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<SigningKey> {
        Self::from_slice(bytes)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
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
        self.sign_prehash(&digest.finalize())
    }
}

impl PrehashSigner<Signature> for SigningKey {
    fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature> {
        // Handle `k = 0` by retrying signature with different `aux_rand`. The chances of this
        // occurring are infinitesimal and a single retry should be sufficient.
        for i in 0..=u8::MAX {
            let mut aux_rand = [0u8; AUX_RAND_BYTES];
            aux_rand[0] = i;

            if let Ok(sig) = self.sign_raw(prehash, &aux_rand) {
                return Ok(sig);
            }
        }

        Err(Error::new())
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

        let mut aux_rand = [0u8; AUX_RAND_BYTES];
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
        let mut aux_rand = [0u8; AUX_RAND_BYTES];
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
