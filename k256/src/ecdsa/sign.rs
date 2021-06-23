//! ECDSA signer

use super::{recoverable, Error, Signature, VerifyingKey};
use crate::{FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, Secp256k1, SecretKey};
use core::{
    borrow::Borrow,
    fmt::{self, Debug},
};
use ecdsa_core::{
    hazmat::{FromDigest, RecoverableSignPrimitive},
    rfc6979,
    signature::{
        digest::{BlockInput, FixedOutput, Reset, Update},
        DigestSigner, RandomizedDigestSigner,
    },
};
use elliptic_curve::{
    consts::U32,
    ops::Invert,
    rand_core::{CryptoRng, RngCore},
    subtle::{Choice, ConstantTimeEq},
};

#[cfg(any(feature = "keccak256", feature = "sha256"))]
use ecdsa_core::signature::{self, digest::Digest, PrehashSignature, RandomizedSigner};

#[cfg(feature = "pkcs8")]
use crate::pkcs8::{self, FromPrivateKey};

#[cfg(feature = "pem")]
use core::str::FromStr;

/// ECDSA/secp256k1 signing key
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
#[derive(Clone)]
pub struct SigningKey {
    /// Inner secret key value
    inner: NonZeroScalar,
}

impl SigningKey {
    /// Generate a cryptographically random [`SigningKey`].
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        Self {
            inner: NonZeroScalar::random(rng),
        }
    }

    /// Initialize [`SigningKey`] from a raw scalar value (big endian).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let inner = SecretKey::from_bytes(bytes)
            .map(|sk| sk.to_secret_scalar())
            .map_err(|_| Error::new())?;

        Ok(Self { inner })
    }

    /// Get the [`VerifyingKey`] which corresponds to this [`SigningKey`].
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: PublicKey::from_secret_scalar(&self.inner).into(),
        }
    }

    /// Legacy alias for [`SigningKey::verifying_key`].
    #[deprecated(since = "0.9.3", note = "use `verifying_key()` instead")]
    pub fn verify_key(&self) -> VerifyingKey {
        self.verifying_key()
    }

    /// Serialize this [`SigningKey`] as bytes
    pub fn to_bytes(&self) -> FieldBytes {
        self.inner.to_bytes()
    }
}

#[cfg(any(feature = "keccak256", feature = "sha256"))]
impl<S> signature::Signer<S> for SigningKey
where
    S: PrehashSignature,
    Self: DigestSigner<S::Digest, S>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<S, Error> {
        self.try_sign_digest(Digest::chain(S::Digest::new(), msg))
    }
}

#[cfg(any(feature = "keccak256", feature = "sha256"))]
impl<S> RandomizedSigner<S> for SigningKey
where
    S: PrehashSignature,
    Self: RandomizedDigestSigner<S::Digest, S>,
{
    fn try_sign_with_rng(&self, rng: impl CryptoRng + RngCore, msg: &[u8]) -> Result<S, Error> {
        self.try_sign_digest_with_rng(rng, S::Digest::new().chain(msg))
    }
}

impl<D> DigestSigner<D, Signature> for SigningKey
where
    D: BlockInput + FixedOutput<OutputSize = U32> + Clone + Default + Reset + Update,
{
    fn try_sign_digest(&self, digest: D) -> Result<Signature, Error> {
        let sig: recoverable::Signature = self.try_sign_digest(digest)?;
        Ok(sig.into())
    }
}

impl<D> DigestSigner<D, recoverable::Signature> for SigningKey
where
    D: BlockInput + FixedOutput<OutputSize = U32> + Clone + Default + Reset + Update,
{
    fn try_sign_digest(&self, digest: D) -> Result<recoverable::Signature, Error> {
        let ephemeral_scalar = rfc6979::generate_k(&self.inner, digest.clone(), &[]);
        let msg_scalar = Scalar::from_digest(digest);
        let (signature, recovery_id) = self
            .inner
            .try_sign_recoverable_prehashed(ephemeral_scalar.as_ref(), &msg_scalar)?;

        recoverable::Signature::new(&signature, recoverable::Id(recovery_id as u8))
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey
where
    D: BlockInput + FixedOutput<OutputSize = U32> + Clone + Default + Reset + Update,
{
    fn try_sign_digest_with_rng(
        &self,
        rng: impl CryptoRng + RngCore,
        digest: D,
    ) -> Result<Signature, Error> {
        let sig: recoverable::Signature = self.try_sign_digest_with_rng(rng, digest)?;
        Ok(sig.into())
    }
}

impl<D> RandomizedDigestSigner<D, recoverable::Signature> for SigningKey
where
    D: BlockInput + FixedOutput<OutputSize = U32> + Clone + Default + Reset + Update,
{
    fn try_sign_digest_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        digest: D,
    ) -> Result<recoverable::Signature, Error> {
        let mut added_entropy = FieldBytes::default();
        rng.fill_bytes(&mut added_entropy);

        let ephemeral_scalar = rfc6979::generate_k(&self.inner, digest.clone(), &added_entropy);
        let msg_scalar = Scalar::from_digest(digest);
        let (signature, is_r_odd) = self
            .inner
            .try_sign_recoverable_prehashed(ephemeral_scalar.as_ref(), &msg_scalar)?;

        recoverable::Signature::new(&signature, recoverable::Id(is_r_odd as u8))
    }
}

impl RecoverableSignPrimitive<Secp256k1> for Scalar {
    #[allow(non_snake_case, clippy::many_single_char_names)]
    fn try_sign_recoverable_prehashed<K>(
        &self,
        ephemeral_scalar: &K,
        z: &Scalar,
    ) -> Result<(Signature, bool), Error>
    where
        K: Borrow<Scalar> + Invert<Output = Scalar>,
    {
        let k_inverse = ephemeral_scalar.invert();
        let k = ephemeral_scalar.borrow();

        if k_inverse.is_none().into() || k.is_zero().into() {
            return Err(Error::new());
        }

        let k_inverse = k_inverse.unwrap();

        // Compute 𝐑 = 𝑘×𝑮
        let R = (ProjectivePoint::generator() * k).to_affine();

        // Lift x-coordinate of 𝐑 (element of base field) into a serialized big
        // integer, then reduce it into an element of the scalar field
        let r = Scalar::from_bytes_reduced(&R.x.to_bytes());

        // Compute `s` as a signature over `r` and `z`.
        let s = k_inverse * (z + (r * self));

        if s.is_zero().into() {
            return Err(Error::new());
        }

        let mut signature = Signature::from_scalars(r, s)?;
        let is_r_odd = bool::from(R.y.normalize().is_odd());
        let is_s_high = signature.normalize_s()?;
        Ok((signature, is_r_odd ^ is_s_high))
    }
}

impl ConstantTimeEq for SigningKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO(tarcieri): use `finish_non_exhaustive` when stable
        f.debug_tuple("SigningKey").field(&"...").finish()
    }
}

impl Eq for SigningKey {}

impl PartialEq for SigningKey {
    fn eq(&self, other: &SigningKey) -> bool {
        self.ct_eq(other).into()
    }
}

impl From<SecretKey> for SigningKey {
    fn from(secret_key: SecretKey) -> SigningKey {
        Self::from(&secret_key)
    }
}

impl From<&SecretKey> for SigningKey {
    fn from(secret_key: &SecretKey) -> SigningKey {
        Self {
            inner: secret_key.to_secret_scalar(),
        }
    }
}

impl From<SigningKey> for SecretKey {
    fn from(signing_key: SigningKey) -> SecretKey {
        signing_key.inner.into()
    }
}

impl From<&SigningKey> for SecretKey {
    fn from(signing_key: &SigningKey) -> SecretKey {
        signing_key.inner.into()
    }
}

impl From<SigningKey> for VerifyingKey {
    fn from(signing_key: SigningKey) -> VerifyingKey {
        signing_key.verifying_key()
    }
}

impl From<&SigningKey> for VerifyingKey {
    fn from(signing_key: &SigningKey) -> VerifyingKey {
        signing_key.verifying_key()
    }
}

impl From<NonZeroScalar> for SigningKey {
    fn from(secret_scalar: NonZeroScalar) -> Self {
        Self {
            inner: secret_scalar,
        }
    }
}

impl From<&NonZeroScalar> for SigningKey {
    fn from(secret_scalar: &NonZeroScalar) -> Self {
        Self {
            inner: *secret_scalar,
        }
    }
}

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
impl FromPrivateKey for SigningKey {
    fn from_pkcs8_private_key_info(
        private_key_info: pkcs8::PrivateKeyInfo<'_>,
    ) -> pkcs8::Result<Self> {
        SecretKey::from_pkcs8_private_key_info(private_key_info).map(Into::into)
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl FromStr for SigningKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_pkcs8_pem(s).map_err(|_| Error::new())
    }
}

#[cfg(test)]
mod tests {
    use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, Secp256k1};
    ecdsa_core::new_signing_test!(Secp256k1, ECDSA_TEST_VECTORS);
}
