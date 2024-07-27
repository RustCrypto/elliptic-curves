//! Support for verifying SM2DSA signatures.
//!
//! ## Algorithm
//!
//! ```text
//! B1: verify whether r' in [1,n-1], verification failed if not
//! B2: verify whether s' in [1,n-1], verification failed if not
//! B3: set M'~=ZA || M'
//! B4: calculate e'=Hv(M'~)
//! B5: calculate t = (r' + s') modn, verification failed if t=0
//! B6: calculate the point (x1', y1')=[s']G + [t]PA
//! B7: calculate R=(e'+x1') modn, verification pass if yes, otherwise failed
//! ```

use super::Signature;
use crate::{
    distid::hash_z, AffinePoint, DistId, EncodedPoint, FieldBytes, Hash, ProjectivePoint,
    PublicKey, Scalar, Sm2,
};
use elliptic_curve::{
    array::typenum::Unsigned,
    ops::{LinearCombination, Reduce},
    point::AffineCoordinates,
    sec1::ToEncodedPoint,
    Curve, Group,
};
use signature::{hazmat::PrehashVerifier, Error, Result, Verifier};
use sm3::{digest::Digest, Sm3};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String};

/// SM2DSA public key used for verifying signatures are valid for a given
/// message.
///
/// ## Usage
///
/// The [`signature`] crate defines the following traits which are the
/// primary API for verifying:
///
/// - [`Verifier`]: verify a message against a provided key and signature
/// - [`PrehashVerifier`]: verify the low-level raw output bytes of a message digest
///
/// # `serde` support
///
/// When the `serde` feature of this crate is enabled, it provides support for
/// serializing and deserializing ECDSA signatures using the `Serialize` and
/// `Deserialize` traits.
///
/// The serialization leverages the encoding used by the [`PublicKey`] type,
/// which is a binary-oriented ASN.1 DER encoding.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    /// Signer's public key.
    public_key: PublicKey,

    /// Signer's user information hash `Z`.
    identity_hash: Hash,

    /// Distinguishing identifier used to compute `Z`.
    #[cfg(feature = "alloc")]
    distid: String,
}

impl VerifyingKey {
    /// Initialize [`VerifyingKey`] from a signer's distinguishing identifier
    /// and public key.
    pub fn new(distid: &DistId, public_key: PublicKey) -> Result<Self> {
        let identity_hash = hash_z(distid, &public_key).map_err(|_| Error::new())?;

        Ok(Self {
            identity_hash,
            public_key,
            #[cfg(feature = "alloc")]
            distid: distid.into(),
        })
    }

    /// Initialize [`VerifyingKey`] from a SEC1-encoded public key.
    pub fn from_sec1_bytes(distid: &DistId, bytes: &[u8]) -> Result<Self> {
        let public_key = PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::new())?;
        Self::new(distid, public_key)
    }

    /// Initialize [`VerifyingKey`] from an affine point.
    ///
    /// Returns an [`Error`] if the given affine point is the additive identity
    /// (a.k.a. point at infinity).
    pub fn from_affine(distid: &DistId, affine: AffinePoint) -> Result<Self> {
        let public_key = PublicKey::from_affine(affine).map_err(|_| Error::new())?;
        Self::new(distid, public_key)
    }

    /// Borrow the inner [`AffinePoint`] for this public key.
    pub fn as_affine(&self) -> &AffinePoint {
        self.public_key.as_affine()
    }

    /// Get the distinguishing identifier for this key.
    #[cfg(feature = "alloc")]
    pub fn distid(&self) -> &DistId {
        self.distid.as_str()
    }

    /// Convert this [`VerifyingKey`] into the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3
    /// (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    #[cfg(feature = "alloc")]
    pub fn to_sec1_bytes(&self) -> Box<[u8]> {
        self.public_key.to_sec1_bytes()
    }

    /// Compute message hash `e` according to [draft-shen-sm2-ecdsa § 5.2.1]
    ///
    /// [draft-shen-sm2-ecdsa § 5.2.1]: https://datatracker.ietf.org/doc/html/draft-shen-sm2-ecdsa-02#section-5.2.1
    pub(crate) fn hash_msg(&self, msg: &[u8]) -> Hash {
        Sm3::new_with_prefix(self.identity_hash)
            .chain_update(msg)
            .finalize()
    }
}

//
// `*Verifier` trait impls
//

impl PrehashVerifier<Signature> for VerifyingKey {
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature) -> Result<()> {
        if prehash.len() != <Sm2 as Curve>::FieldBytesSize::USIZE {
            return Err(Error::new());
        }

        // B1: verify whether r' in [1,n-1], verification failed if not
        let r = signature.r(); // NonZeroScalar checked at signature parse time

        // B2: verify whether s' in [1,n-1], verification failed if not
        let s = signature.s(); // NonZeroScalar checked at signature parse time

        // B4: calculate e'=Hv(M'~)
        #[allow(deprecated)] // from_slice
        let e = Scalar::reduce_bytes(FieldBytes::from_slice(prehash));

        // B5: calculate t = (r' + s') modn, verification failed if t=0
        let t = *r + *s;
        if t.is_zero().into() {
            return Err(Error::new());
        }

        // B6: calculate the point (x1', y1')=[s']G + [t]PA
        let x = ProjectivePoint::lincomb(&[
            (ProjectivePoint::generator(), *s),
            (ProjectivePoint::from(&self.public_key), t),
        ])
        .to_affine()
        .x();

        // B7: calculate R=(e'+x1') modn, verification pass if yes, otherwise failed
        if *r == e + Scalar::reduce_bytes(&x) {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<()> {
        // B3: set M'~=ZA || M'
        let hash = self.hash_msg(msg);
        self.verify_prehash(&hash, signature)
    }
}

//
// Other trait impls
//

impl AsRef<AffinePoint> for VerifyingKey {
    fn as_ref(&self) -> &AffinePoint {
        self.as_affine()
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(verifying_key: VerifyingKey) -> PublicKey {
        verifying_key.public_key
    }
}

impl From<&VerifyingKey> for PublicKey {
    fn from(verifying_key: &VerifyingKey) -> PublicKey {
        verifying_key.public_key
    }
}

impl ToEncodedPoint<Sm2> for VerifyingKey {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        self.as_affine().to_encoded_point(compress)
    }
}
