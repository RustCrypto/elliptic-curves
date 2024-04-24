//! Taproot Schnorr verifying key.

use super::{tagged_hash, Signature, CHALLENGE_TAG};
use crate::{AffinePoint, FieldBytes, ProjectivePoint, PublicKey, Scalar};
use elliptic_curve::{
    bigint::U256,
    group::prime::PrimeCurveAffine,
    ops::{LinearCombination, Reduce},
    point::DecompactPoint,
};
use sha2::{
    digest::{consts::U32, FixedOutput},
    Digest, Sha256,
};
use signature::{hazmat::PrehashVerifier, DigestVerifier, Error, Result, Verifier};

#[cfg(feature = "serde")]
use serdect::serde::{de, ser, Deserialize, Serialize};

/// Taproot Schnorr verifying key.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VerifyingKey {
    /// Inner public key
    pub(super) inner: PublicKey,
}

impl VerifyingKey {
    /// Borrow the inner [`AffinePoint`] this type wraps.
    pub fn as_affine(&self) -> &AffinePoint {
        self.inner.as_affine()
    }

    /// Serialize as bytes.
    pub fn to_bytes(&self) -> FieldBytes {
        self.as_affine().x.to_bytes()
    }

    /// Compute Schnorr signature.
    ///
    /// # ⚠️ Warning
    ///
    /// This is a low-level interface intended only for unusual use cases
    /// involving verifying pre-hashed messages, or "raw" messages where the
    /// message is not hashed at all prior to being used to generate the
    /// Schnorr signature.
    ///
    /// The preferred interfaces are the [`DigestVerifier`] or [`PrehashVerifier`] traits.
    pub fn verify_raw(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> core::result::Result<(), Error> {
        let (r, s) = signature.split();

        let e = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(signature.r.to_bytes())
                .chain_update(self.to_bytes())
                .chain_update(message)
                .finalize(),
        );

        let R = ProjectivePoint::lincomb(
            &ProjectivePoint::GENERATOR,
            s,
            &self.inner.to_projective(),
            &-e,
        )
        .to_affine();

        if R.is_identity().into() || R.y.normalize().is_odd().into() || R.x.normalize() != *r {
            return Err(Error::new());
        }

        Ok(())
    }

    /// Parse verifying key from big endian-encoded x-coordinate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let maybe_affine_point = AffinePoint::decompact(FieldBytes::from_slice(bytes));
        let affine_point = Option::from(maybe_affine_point).ok_or_else(Error::new)?;
        PublicKey::from_affine(affine_point)
            .map_err(|_| Error::new())?
            .try_into()
    }
}

//
// `*Verifier` trait impls
//

impl<D> DigestVerifier<D, Signature> for VerifyingKey
where
    D: Digest + FixedOutput<OutputSize = U32>,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> Result<()> {
        self.verify_prehash(digest.finalize_fixed().as_slice(), signature)
    }
}

impl PrehashVerifier<Signature> for VerifyingKey {
    fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &Signature,
    ) -> core::result::Result<(), Error> {
        self.verify_raw(prehash, signature)
    }
}

impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<()> {
        self.verify_digest(Sha256::new_with_prefix(msg), signature)
    }
}

//
// Other trait impls
//

impl From<VerifyingKey> for AffinePoint {
    fn from(vk: VerifyingKey) -> AffinePoint {
        *vk.as_affine()
    }
}

impl From<&VerifyingKey> for AffinePoint {
    fn from(vk: &VerifyingKey) -> AffinePoint {
        *vk.as_affine()
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(vk: VerifyingKey) -> PublicKey {
        vk.inner
    }
}

impl From<&VerifyingKey> for PublicKey {
    fn from(vk: &VerifyingKey) -> PublicKey {
        vk.inner
    }
}

impl TryFrom<PublicKey> for VerifyingKey {
    type Error = Error;

    fn try_from(public_key: PublicKey) -> Result<VerifyingKey> {
        if public_key.as_affine().y.normalize().is_even().into() {
            Ok(Self { inner: public_key })
        } else {
            Err(Error::new())
        }
    }
}

impl TryFrom<&PublicKey> for VerifyingKey {
    type Error = Error;

    fn try_from(public_key: &PublicKey) -> Result<VerifyingKey> {
        Self::try_from(*public_key)
    }
}

#[cfg(feature = "serde")]
impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        VerifyingKey::try_from(PublicKey::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}
