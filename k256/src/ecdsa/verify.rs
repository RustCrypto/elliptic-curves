//! ECDSA verifier

use super::{recoverable, Error, Signature};
use crate::{
    lincomb, AffinePoint, CompressedPoint, EncodedPoint, ProjectivePoint, PublicKey, Scalar,
    Secp256k1,
};
use core::convert::TryFrom;
use ecdsa_core::{hazmat::VerifyPrimitive, signature};
use elliptic_curve::{consts::U32, ops::Invert, sec1::ToEncodedPoint};
use signature::{digest::Digest, DigestVerifier};

#[cfg(feature = "sha256")]
use signature::PrehashSignature;

#[cfg(feature = "pkcs8")]
use crate::pkcs8::{self, FromPublicKey};

#[cfg(feature = "pem")]
use core::str::FromStr;

/// ECDSA/secp256k1 verification key (i.e. public key)
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct VerifyingKey {
    /// Core ECDSA verify key
    pub(super) inner: ecdsa_core::VerifyingKey<Secp256k1>,
}

impl VerifyingKey {
    /// Initialize [`VerifyingKey`] from a SEC1-encoded public key.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Error> {
        ecdsa_core::VerifyingKey::from_sec1_bytes(bytes).map(|key| VerifyingKey { inner: key })
    }

    /// Initialize [`VerifyingKey`] from a SEC1 [`EncodedPoint`].
    // TODO(tarcieri): switch to using `FromEncodedPoint` trait?
    pub fn from_encoded_point(public_key: &EncodedPoint) -> Result<Self, Error> {
        ecdsa_core::VerifyingKey::from_encoded_point(public_key)
            .map(|key| VerifyingKey { inner: key })
    }

    /// Serialize this [`VerifyingKey`] as a SEC1-encoded bytestring
    /// (with point compression applied)
    pub fn to_bytes(&self) -> CompressedPoint {
        CompressedPoint::clone_from_slice(EncodedPoint::from(self).as_bytes())
    }
}

#[cfg(feature = "sha256")]
impl<S> signature::Verifier<S> for VerifyingKey
where
    S: PrehashSignature,
    Self: DigestVerifier<S::Digest, S>,
{
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
        self.verify_digest(S::Digest::new().chain(msg), signature)
    }
}

impl<D> DigestVerifier<D, Signature> for VerifyingKey
where
    D: Digest<OutputSize = U32>,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> Result<(), Error> {
        self.inner.verify_digest(digest, signature)
    }
}

impl<D> DigestVerifier<D, recoverable::Signature> for VerifyingKey
where
    D: Digest<OutputSize = U32>,
{
    fn verify_digest(&self, digest: D, signature: &recoverable::Signature) -> Result<(), Error> {
        self.inner
            .verify_digest(digest, &Signature::from(*signature))
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

        let x = lincomb(
            &ProjectivePoint::generator(),
            &u1,
            &ProjectivePoint::from(*self),
            &u2,
        )
        .to_affine()
        .x;

        if Scalar::from_bytes_reduced(&x.to_bytes()).eq(&r) {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

impl From<PublicKey> for VerifyingKey {
    fn from(public_key: PublicKey) -> VerifyingKey {
        Self {
            inner: public_key.into(),
        }
    }
}

impl From<&PublicKey> for VerifyingKey {
    fn from(public_key: &PublicKey) -> VerifyingKey {
        public_key.clone().into()
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(verifying_key: VerifyingKey) -> PublicKey {
        verifying_key.inner.into()
    }
}

impl From<&VerifyingKey> for PublicKey {
    fn from(verifying_key: &VerifyingKey) -> PublicKey {
        verifying_key.inner.clone().into()
    }
}

impl From<&AffinePoint> for VerifyingKey {
    fn from(affine_point: &AffinePoint) -> VerifyingKey {
        VerifyingKey::from_encoded_point(&affine_point.to_encoded_point(false)).unwrap()
    }
}

impl From<&VerifyingKey> for EncodedPoint {
    fn from(verify_key: &VerifyingKey) -> EncodedPoint {
        verify_key.to_encoded_point(true)
    }
}

impl ToEncodedPoint<Secp256k1> for VerifyingKey {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        self.inner.to_encoded_point(compress)
    }
}

impl TryFrom<&EncodedPoint> for VerifyingKey {
    type Error = Error;

    fn try_from(encoded_point: &EncodedPoint) -> Result<Self, Error> {
        Self::from_encoded_point(encoded_point)
    }
}

#[cfg(feature = "pkcs8")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs8")))]
impl FromPublicKey for VerifyingKey {
    fn from_spki(spki: pkcs8::SubjectPublicKeyInfo<'_>) -> pkcs8::Result<Self> {
        PublicKey::from_spki(spki).map(|pk| Self { inner: pk.into() })
    }
}

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
impl FromStr for VerifyingKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_public_key_pem(s).map_err(|_| Error::new())
    }
}

#[cfg(test)]
mod tests {
    use super::VerifyingKey;
    use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, Secp256k1};
    use ecdsa_core::signature::Verifier;
    use hex_literal::hex;

    ecdsa_core::new_verification_test!(Secp256k1, ECDSA_TEST_VECTORS);

    /// Wycheproof tcId: 304
    #[test]
    fn malleability_edge_case_valid() {
        let verifying_key_bytes = hex!("043a3150798c8af69d1e6e981f3a45402ba1d732f4be8330c5164f49e10ec555b4221bd842bc5e4d97eff37165f60e3998a424d72a450cf95ea477c78287d0343a");
        let verifying_key = VerifyingKey::from_sec1_bytes(&verifying_key_bytes).unwrap();

        let msg = hex!("313233343030");
        let mut sig = Signature::from_der(&hex!("304402207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a002207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0")).unwrap();
        assert!(!sig.normalize_s().unwrap());
        assert!(verifying_key.verify(&msg, &sig).is_ok());
    }
}
