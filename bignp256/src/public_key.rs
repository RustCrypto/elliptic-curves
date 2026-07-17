//! Public key types and traits

#[cfg(feature = "pkcs8")]
use crate::ALGORITHM_OID;
use crate::{AffinePoint, BignP256, NonZeroScalar, ProjectivePoint, Sec1Point};
#[cfg(feature = "pem")]
use core::{fmt::Display, str::FromStr};
#[cfg(feature = "pkcs8")]
use elliptic_curve::pkcs8::{
    self, AssociatedOid, DecodePublicKey, EncodePublicKey, ObjectIdentifier,
    spki::{AlgorithmIdentifier, AssociatedAlgorithmIdentifier},
};
use elliptic_curve::{Error, array::Array, point::NonIdentity, sec1::ToSec1Point};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, fmt};

/// Elliptic curve BignP256 public key.
///
/// A wrapper around [`elliptic_curve::PublicKey`] which uses the raw
/// (untagged) point encoding and the PKCS#8 algorithm identifier defined in
/// STB 34.101.45 instead of the SEC1/RFC 5480 ones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKey(elliptic_curve::PublicKey<BignP256>);

impl PublicKey {
    /// Convert an [`AffinePoint`] into a [`PublicKey`]
    pub fn from_affine(point: AffinePoint) -> Result<Self, Error> {
        elliptic_curve::PublicKey::from_affine(point).map(Self)
    }

    /// Compute a [`PublicKey`] from a secret [`NonZeroScalar`] value
    /// (i.e. a secret key represented as a raw scalar value)
    pub fn from_secret_scalar(scalar: &NonZeroScalar) -> Self {
        Self(elliptic_curve::PublicKey::from_secret_scalar(scalar))
    }

    /// Borrow the inner [`AffinePoint`] from this [`PublicKey`].
    ///
    /// In ECC, public keys are elliptic curve points.
    pub fn as_affine(&self) -> &AffinePoint {
        self.0.as_affine()
    }

    /// Convert this [`PublicKey`] to a [`ProjectivePoint`] for the given curve
    pub fn to_projective(&self) -> ProjectivePoint {
        self.0.to_projective()
    }

    /// Convert this [`PublicKey`] to a [`NonIdentity`] of the inner [`AffinePoint`]
    pub fn to_nonidentity(&self) -> NonIdentity<AffinePoint> {
        self.0.to_nonidentity()
    }

    /// Parse a [`PublicKey`] from the raw (untagged) point encoding defined
    /// in STB 34.101.45.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = Array::try_from(bytes).map_err(|_| Error)?;
        Self::from_sec1_point(Sec1Point::from_untagged_bytes(&bytes))
    }

    /// Get [`PublicKey`] from encoded point
    pub fn from_sec1_point(point: Sec1Point) -> Result<Self, Error> {
        elliptic_curve::PublicKey::try_from(&point).map(Self)
    }

    /// Serialize this [`PublicKey`] using the raw (untagged) point encoding
    /// defined in STB 34.101.45.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.to_sec1_point().to_bytes()[1..].into()
    }

    /// Get encoded point from [`PublicKey`]
    pub fn to_sec1_point(&self) -> Sec1Point {
        self.0.to_sec1_point(false)
    }
}

impl AsRef<AffinePoint> for PublicKey {
    fn as_ref(&self) -> &AffinePoint {
        self.as_affine()
    }
}

impl From<NonIdentity<AffinePoint>> for PublicKey {
    fn from(value: NonIdentity<AffinePoint>) -> Self {
        Self(value.into())
    }
}

impl From<&NonIdentity<AffinePoint>> for PublicKey {
    fn from(value: &NonIdentity<AffinePoint>) -> Self {
        Self(value.into())
    }
}

impl From<PublicKey> for NonIdentity<AffinePoint> {
    fn from(value: PublicKey) -> Self {
        value.0.into()
    }
}

impl From<&PublicKey> for NonIdentity<AffinePoint> {
    fn from(value: &PublicKey) -> Self {
        value.0.into()
    }
}

impl From<PublicKey> for elliptic_curve::PublicKey<BignP256> {
    fn from(value: PublicKey) -> Self {
        value.0
    }
}

impl From<elliptic_curve::PublicKey<BignP256>> for PublicKey {
    fn from(value: elliptic_curve::PublicKey<BignP256>) -> Self {
        Self(value)
    }
}

impl From<PublicKey> for Sec1Point {
    fn from(value: PublicKey) -> Self {
        value.to_sec1_point()
    }
}

#[cfg(feature = "pkcs8")]
impl AssociatedAlgorithmIdentifier for PublicKey {
    type Params = ObjectIdentifier;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<ObjectIdentifier> = AlgorithmIdentifier {
        oid: ALGORITHM_OID,
        parameters: Some(BignP256::OID),
    };
}

#[cfg(feature = "pkcs8")]
impl TryFrom<pkcs8::SubjectPublicKeyInfoRef<'_>> for PublicKey {
    type Error = pkcs8::spki::Error;

    fn try_from(spki: pkcs8::SubjectPublicKeyInfoRef<'_>) -> pkcs8::spki::Result<Self> {
        Self::try_from(&spki)
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<&pkcs8::SubjectPublicKeyInfoRef<'_>> for PublicKey {
    type Error = pkcs8::spki::Error;

    fn try_from(spki: &pkcs8::SubjectPublicKeyInfoRef<'_>) -> pkcs8::spki::Result<Self> {
        spki.algorithm.assert_oids(ALGORITHM_OID, BignP256::OID)?;

        let public_key_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| der::Tag::BitString.value_error().to_error())?;

        Self::from_bytes(public_key_bytes).map_err(|_| pkcs8::spki::Error::KeyMalformed)
    }
}

#[cfg(all(feature = "alloc", feature = "pkcs8"))]
impl EncodePublicKey for PublicKey {
    fn to_public_key_der(&self) -> pkcs8::spki::Result<der::Document> {
        let pk_bytes = self.to_bytes();
        let subject_public_key = der::asn1::BitStringRef::new(0, &pk_bytes)?;

        pkcs8::SubjectPublicKeyInfo {
            algorithm: Self::ALGORITHM_IDENTIFIER,
            subject_public_key,
        }
        .try_into()
    }
}

#[cfg(feature = "pem")]
impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_public_key_pem(s).map_err(|_| Error)
    }
}

#[cfg(feature = "pem")]
impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.to_public_key_pem(Default::default())
                .expect("PEM encoding error")
        )
    }
}
