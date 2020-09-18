//! ECDSA verifier

use super::{recoverable, Error, Signature};
use crate::{AffinePoint, CompressedPoint, EncodedPoint, ProjectivePoint, Scalar, Secp256k1};
use core::convert::TryFrom;
use ecdsa_core::{hazmat::VerifyPrimitive, signature};
use elliptic_curve::{consts::U32, ops::Invert, sec1::ToEncodedPoint};
use signature::{digest::Digest, DigestVerifier};

#[cfg(feature = "sha256")]
use signature::PrehashSignature;

/// ECDSA/secp256k1 verification key (i.e. public key)
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyKey {
    /// Core ECDSA verify key
    pub(super) key: ecdsa_core::VerifyKey<Secp256k1>,
}

impl VerifyKey {
    /// Initialize [`VerifyKey`] from a SEC1-encoded public key.
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        ecdsa_core::VerifyKey::new(bytes).map(|key| VerifyKey { key })
    }

    /// Initialize [`VerifyKey`] from a SEC1 [`EncodedPoint`].
    pub fn from_encoded_point(public_key: &EncodedPoint) -> Result<Self, Error> {
        ecdsa_core::VerifyKey::from_encoded_point(public_key).map(|key| VerifyKey { key })
    }

    /// Serialize this [`VerifyKey`] as a SEC1-encoded bytestring
    /// (with point compression applied)
    pub fn to_bytes(&self) -> CompressedPoint {
        let mut result = [0u8; 33];
        result.copy_from_slice(EncodedPoint::from(self).as_ref());
        result
    }
}

#[cfg(feature = "sha256")]
impl<S> signature::Verifier<S> for VerifyKey
where
    S: PrehashSignature,
    Self: DigestVerifier<S::Digest, S>,
{
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
        self.verify_digest(S::Digest::new().chain(msg), signature)
    }
}

impl<D> DigestVerifier<D, Signature> for VerifyKey
where
    D: Digest<OutputSize = U32>,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> Result<(), Error> {
        self.key.verify_digest(digest, signature)
    }
}

impl<D> DigestVerifier<D, recoverable::Signature> for VerifyKey
where
    D: Digest<OutputSize = U32>,
{
    fn verify_digest(&self, digest: D, signature: &recoverable::Signature) -> Result<(), Error> {
        self.key.verify_digest(digest, &Signature::from(*signature))
    }
}

impl From<&AffinePoint> for VerifyKey {
    fn from(affine_point: &AffinePoint) -> VerifyKey {
        VerifyKey::from_encoded_point(&affine_point.to_encoded_point(false)).unwrap()
    }
}

impl From<&VerifyKey> for EncodedPoint {
    fn from(verify_key: &VerifyKey) -> EncodedPoint {
        verify_key.key.to_encoded_point(true)
    }
}

impl TryFrom<&EncodedPoint> for VerifyKey {
    type Error = Error;

    fn try_from(encoded_point: &EncodedPoint) -> Result<Self, Error> {
        Self::from_encoded_point(encoded_point)
    }
}

impl VerifyPrimitive<Secp256k1> for AffinePoint {
    fn verify_prehashed(&self, z: &Scalar, signature: &Signature) -> Result<(), Error> {
        let r = signature.r();
        let s = signature.s();

        // Ensure signature is "low S" normalized ala BIP 0062
        if s.is_high().into() {
            return Err(Error::new());
        }

        let s_inv = s.invert().unwrap();
        let u1 = z * &s_inv;
        let u2 = *r * s_inv;

        let x = ((ProjectivePoint::generator() * u1) + (ProjectivePoint::from(*self) * u2))
            .to_affine()
            .x;

        if Scalar::from_bytes_reduced(&x.to_bytes()).eq(&r) {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, Secp256k1};
    ecdsa_core::new_verification_test!(Secp256k1, ECDSA_TEST_VECTORS);
}
