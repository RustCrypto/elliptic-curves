//! ECDSA signer

use super::{recoverable, Error, Signature, VerifyKey};
use crate::{FieldBytes, NonZeroScalar, ProjectivePoint, Scalar, Secp256k1, SecretKey};
use core::{borrow::Borrow, convert::TryInto};
use ecdsa_core::{
    hazmat::SignPrimitive,
    rfc6979,
    signature::{DigestSigner, RandomizedDigestSigner},
};
use elliptic_curve::{
    consts::U32,
    digest::{BlockInput, FixedOutput, Reset, Update},
    ops::Invert,
    rand_core::{CryptoRng, RngCore},
    FromDigest,
};

#[cfg(any(feature = "keccak256", feature = "sha256"))]
use ecdsa_core::signature::{self, digest::Digest, PrehashSignature, RandomizedSigner};

/// ECDSA/secp256k1 signing key
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub struct SigningKey {
    /// Secret scalar value
    secret_scalar: NonZeroScalar,
}

impl SigningKey {
    /// Generate a cryptographically random [`SigningKey`].
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        Self {
            secret_scalar: NonZeroScalar::random(rng),
        }
    }

    /// Initialize [`SigningKey`] from a raw scalar value (big endian).
    // TODO(tarcieri): PKCS#8 support
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .try_into()
            .ok()
            .map(|secret_scalar| Self { secret_scalar })
            .ok_or_else(Error::new)
    }

    /// Get the [`VerifyKey`] which corresponds to this [`SigningKey`]
    pub fn verify_key(&self) -> VerifyKey {
        VerifyKey {
            key: ecdsa_core::SigningKey::from(self.secret_scalar).verify_key(),
        }
    }

    /// Serialize this [`SigningKey`] as bytes
    pub fn to_bytes(&self) -> FieldBytes {
        self.secret_scalar.to_bytes()
    }
}

impl From<&SecretKey> for SigningKey {
    fn from(secret_key: &SecretKey) -> Self {
        Self {
            secret_scalar: NonZeroScalar::new(*secret_key.secret_scalar())
                .expect("invalid secret scalar"),
        }
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
        ecdsa_core::SigningKey::from(self.secret_scalar).try_sign_digest(digest)
    }
}

impl<D> DigestSigner<D, recoverable::Signature> for SigningKey
where
    D: BlockInput + FixedOutput<OutputSize = U32> + Clone + Default + Reset + Update,
{
    fn try_sign_digest(&self, digest: D) -> Result<recoverable::Signature, Error> {
        let ephemeral_scalar = rfc6979::generate_k(&self.secret_scalar, digest.clone(), &[]);
        let msg_scalar = Scalar::from_digest(digest);
        self.secret_scalar
            .try_sign_recoverable_prehashed(ephemeral_scalar.as_ref(), &msg_scalar)
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
        ecdsa_core::SigningKey::from(self.secret_scalar).try_sign_digest_with_rng(rng, digest)
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

        let ephemeral_scalar =
            rfc6979::generate_k(&self.secret_scalar, digest.clone(), &added_entropy);

        let msg_scalar = Scalar::from_digest(digest);
        self.secret_scalar
            .try_sign_recoverable_prehashed(ephemeral_scalar.as_ref(), &msg_scalar)
    }
}

impl From<&SigningKey> for VerifyKey {
    fn from(signing_key: &SigningKey) -> VerifyKey {
        signing_key.verify_key()
    }
}

impl SignPrimitive<Secp256k1> for Scalar {
    fn try_sign_prehashed<K: Borrow<Scalar> + Invert<Output = Scalar>>(
        &self,
        ephemeral_scalar: &K,
        hashed_msg: &Scalar,
    ) -> Result<Signature, Error> {
        self.try_sign_recoverable_prehashed(ephemeral_scalar, hashed_msg)
            .map(Into::into)
    }
}

impl Scalar {
    #[allow(non_snake_case, clippy::many_single_char_names)]
    fn try_sign_recoverable_prehashed<K>(
        &self,
        ephemeral_scalar: &K,
        z: &Scalar,
    ) -> Result<recoverable::Signature, Error>
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
        let recovery_id = recoverable::Id((is_r_odd ^ is_s_high) as u8);
        recoverable::Signature::new(&signature, recovery_id)
    }
}

impl From<NonZeroScalar> for SigningKey {
    fn from(secret_scalar: NonZeroScalar) -> Self {
        Self { secret_scalar }
    }
}

#[cfg(test)]
mod tests {
    use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, Secp256k1};
    ecdsa_core::new_signing_test!(Secp256k1, ECDSA_TEST_VECTORS);
}
