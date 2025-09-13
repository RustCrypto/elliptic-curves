//! Taproot Schnorr verifying key.

use super::{CHALLENGE_TAG, Signature, tagged_hash};
use crate::{AffinePoint, FieldBytes, ProjectivePoint, PublicKey, Scalar};
use elliptic_curve::{
    group::prime::PrimeCurveAffine,
    ops::{LinearCombination, Reduce},
    point::DecompactPoint,
};
use sha2::{
    Digest, Sha256,
    digest::{Update, consts::U32},
};
use signature::{
    DigestVerifier, Error, MultipartVerifier, Result, Verifier, hazmat::PrehashVerifier,
};

#[cfg(feature = "serde")]
use serdect::serde::{Deserialize, Serialize, de, ser};

/// Taproot Schnorr verifying key.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VerifyingKey {
    /// Inner public key
    pub(super) inner: PublicKey,
}

impl VerifyingKey {
    /// Parse verifying key from big endian-encoded x-coordinate.
    pub fn from_bytes(x_bytes: &FieldBytes) -> Result<Self> {
        AffinePoint::decompact(x_bytes)
            .into_option()
            .ok_or_else(Error::new)?
            .try_into()
    }

    /// Parse verifying key from big endian-encoded x-coordinate.
    pub fn from_slice(x_bytes: &[u8]) -> Result<Self> {
        let x_bytes = FieldBytes::try_from(x_bytes).map_err(|_| Error::new())?;
        Self::from_bytes(&x_bytes)
    }

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
    pub fn verify_raw(&self, message: &[u8], signature: &Signature) -> Result<()> {
        let (r, s) = signature.split();

        let e = <Scalar as Reduce<FieldBytes>>::reduce(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(signature.r.to_bytes())
                .chain_update(self.to_bytes())
                .chain_update(message)
                .finalize(),
        );

        let R = ProjectivePoint::lincomb(&[
            (ProjectivePoint::GENERATOR, **s),
            (self.inner.to_projective(), -e),
        ])
        .to_affine();

        if R.is_identity().into() || R.y.normalize().is_odd().into() || R.x.normalize() != *r {
            return Err(Error::new());
        }

        Ok(())
    }
}

//
// `*Verifier` trait impls
//

impl<D> DigestVerifier<D, Signature> for VerifyingKey
where
    D: Digest<OutputSize = U32> + Update,
{
    fn verify_digest<F: Fn(&mut D) -> Result<()>>(
        &self,
        f: F,
        signature: &Signature,
    ) -> Result<()> {
        let mut digest = D::new();
        f(&mut digest)?;
        self.verify_prehash(&digest.finalize(), signature)
    }
}

impl PrehashVerifier<Signature> for VerifyingKey {
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature) -> Result<()> {
        self.verify_raw(prehash, signature)
    }
}

impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<()> {
        self.multipart_verify(&[msg], signature)
    }
}

impl MultipartVerifier<Signature> for VerifyingKey {
    fn multipart_verify(&self, msg: &[&[u8]], signature: &Signature) -> Result<()> {
        self.verify_digest(
            |digest: &mut Sha256| {
                msg.iter().for_each(|&slice| Update::update(digest, slice));
                Ok(())
            },
            signature,
        )
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

impl TryFrom<AffinePoint> for VerifyingKey {
    type Error = Error;

    fn try_from(mut point: AffinePoint) -> Result<VerifyingKey> {
        if point.y.normalize().is_odd().into() {
            point = -point;
        }

        PublicKey::try_from(point)
            .map_err(|_| Error::new())?
            .try_into()
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

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = Error;

    fn try_from(x_bytes: &[u8]) -> Result<VerifyingKey> {
        Self::from_slice(x_bytes)
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
