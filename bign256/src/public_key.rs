//! Public key types and traits

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, fmt};
use core::{fmt::Display, str::FromStr};

use elliptic_curve::{
    array::Array,
    point::NonIdentity,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, CurveArithmetic, Error, Group,
};
use pkcs8::{
    spki::{AlgorithmIdentifier, AssociatedAlgorithmIdentifier},
    AssociatedOid, DecodePublicKey, EncodePublicKey, ObjectIdentifier,
};

use crate::{BignP256, EncodedPoint, NonZeroScalar, ProjectivePoint, PublicKey, ALGORITHM_OID};

impl PublicKey {
    /// Convert an [`AffinePoint`] into a [`PublicKey`]
    pub fn from_affine(point: AffinePoint<BignP256>) -> Result<Self, Error> {
        if ProjectivePoint::from(point).is_identity().into() {
            Err(Error)
        } else {
            Ok(Self { point })
        }
    }

    /// Compute a [`PublicKey`] from a secret [`NonZeroScalar`] value
    /// (i.e. a secret key represented as a raw scalar value)
    pub fn from_secret_scalar(scalar: &NonZeroScalar) -> Self {
        // `NonZeroScalar` ensures the resulting point is not the identity
        #[allow(clippy::arithmetic_side_effects)]
        Self {
            point: (<BignP256 as CurveArithmetic>::ProjectivePoint::generator() * scalar.as_ref())
                .to_affine(),
        }
    }

    /// Borrow the inner [`AffinePoint`] from this [`PublicKey`].
    ///
    /// In ECC, public keys are elliptic curve points.
    pub fn as_affine(&self) -> &AffinePoint<BignP256> {
        &self.point
    }

    /// Convert this [`PublicKey`] to a [`ProjectivePoint`] for the given curve
    pub fn to_projective(&self) -> ProjectivePoint {
        self.point.into()
    }

    /// Convert this [`PublicKey`] to a [`NonIdentity`] of the inner [`AffinePoint`]
    pub fn to_nonidentity(&self) -> NonIdentity<AffinePoint<BignP256>> {
        NonIdentity::new(self.point).unwrap()
    }

    /// Get [`PublicKey`] from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut bytes = Array::try_from(bytes).map_err(|_| Error)?;

        // It is because public_key in little endian
        bytes[..32].reverse();
        bytes[32..].reverse();

        let point = EncodedPoint::from_untagged_bytes(&bytes);
        let affine = AffinePoint::<BignP256>::from_encoded_point(&point);
        if affine.is_none().into() {
            Err(Error)
        } else {
            Ok(Self {
                point: affine.unwrap(),
            })
        }
    }

    /// Get [`PublicKey`] from encoded point
    pub fn from_encoded_point(point: EncodedPoint) -> Result<Self, Error> {
        let affine = AffinePoint::<BignP256>::from_encoded_point(&point);
        if affine.is_none().into() {
            Err(Error)
        } else {
            Ok(Self {
                point: affine.unwrap(),
            })
        }
    }

    #[cfg(feature = "alloc")]
    /// Get bytes from [`PublicKey`]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut bytes = self.point.to_encoded_point(false).to_bytes();
        bytes[1..32 + 1].reverse();
        bytes[33..].reverse();
        bytes[1..].to_vec().into_boxed_slice()
    }

    #[cfg(feature = "alloc")]
    /// Get encoded point from [`PublicKey`]
    pub fn to_encoded_point(&self) -> EncodedPoint {
        self.point.to_encoded_point(false)
    }
}

impl AsRef<AffinePoint<BignP256>> for PublicKey {
    fn as_ref(&self) -> &AffinePoint<BignP256> {
        self.as_affine()
    }
}
impl Copy for PublicKey {}
impl From<NonIdentity<AffinePoint<BignP256>>> for PublicKey {
    fn from(value: NonIdentity<AffinePoint<BignP256>>) -> Self {
        Self::from(&value)
    }
}

impl From<&NonIdentity<AffinePoint<BignP256>>> for PublicKey {
    fn from(value: &NonIdentity<AffinePoint<BignP256>>) -> Self {
        Self {
            point: value.to_point(),
        }
    }
}

impl From<PublicKey> for NonIdentity<AffinePoint<BignP256>> {
    fn from(value: PublicKey) -> Self {
        Self::from(&value)
    }
}

impl From<&PublicKey> for NonIdentity<AffinePoint<BignP256>> {
    fn from(value: &PublicKey) -> Self {
        PublicKey::to_nonidentity(value)
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
            .ok_or_else(|| der::Tag::BitString.value_error())?;

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

impl From<PublicKey> for EncodedPoint {
    fn from(value: PublicKey) -> Self {
        value.point.to_encoded_point(false)
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
