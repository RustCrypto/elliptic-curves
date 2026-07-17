//! Bign256 secret key.

use core::fmt::{self, Debug};
#[cfg(feature = "pem")]
use core::str::FromStr;
#[cfg(feature = "pkcs8")]
use der::{SecretDocument, asn1::OctetStringRef};

#[cfg(feature = "pkcs8")]
use crate::ALGORITHM_OID;
use crate::{BignP256, FieldBytes, NonZeroScalar, PublicKey, Result, ScalarValue};
#[cfg(feature = "pem")]
use elliptic_curve::Error;
#[cfg(feature = "pkcs8")]
use elliptic_curve::pkcs8::{
    self, AssociatedOid, DecodePrivateKey, EncodePrivateKey, ObjectIdentifier,
    spki::{AlgorithmIdentifier, AssociatedAlgorithmIdentifier},
};
use elliptic_curve::{Generate, rand_core::TryCryptoRng, zeroize::ZeroizeOnDrop};

/// Elliptic curve BignP256 Secret Key.
///
/// A wrapper around [`elliptic_curve::SecretKey`] which uses the PKCS#8
/// encoding defined in STB 34.101.45 (the raw secret scalar as an octet
/// string with the bign algorithm identifier) instead of SEC1.
#[derive(Clone)]
pub struct SecretKey(elliptic_curve::SecretKey<BignP256>);

impl SecretKey {
    /// Borrow the inner secret [`elliptic_curve::ScalarValue`] value.
    ///
    /// # ⚠️ Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    pub fn as_scalar_value(&self) -> &ScalarValue {
        self.0.as_scalar_value()
    }

    /// Get the secret [`elliptic_curve::NonZeroScalar`] value for this key.
    ///
    /// # ⚠️ Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    pub fn to_nonzero_scalar(&self) -> NonZeroScalar {
        self.0.to_nonzero_scalar()
    }

    /// Get the [`PublicKey`] which corresponds to this secret key
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key().into()
    }

    /// Deserialize secret key from an encoded secret scalar.
    pub fn from_bytes(bytes: &FieldBytes) -> Result<Self> {
        elliptic_curve::SecretKey::from_bytes(bytes).map(Self)
    }

    /// Deserialize secret key from an encoded secret scalar passed as a byte slice.
    ///
    /// The slice is expected to be a minimum of 24-bytes (192-bytes) and at most
    /// `C::FieldBytesSize` bytes in length.
    ///
    /// Byte slices shorter than the field size are handled by zero padding the input.
    ///
    /// NOTE: this function is variable-time with respect to the input length. To avoid a timing
    /// sidechannel, always ensure that the input has been pre-padded to `C::FieldBytesSize`.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        elliptic_curve::SecretKey::from_slice(slice).map(Self)
    }

    /// Serialize raw secret scalar as a big endian integer.
    pub fn to_bytes(&self) -> FieldBytes {
        self.0.to_bytes()
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl From<SecretKey> for NonZeroScalar {
    fn from(secret_key: SecretKey) -> NonZeroScalar {
        secret_key.to_nonzero_scalar()
    }
}

impl From<NonZeroScalar> for SecretKey {
    fn from(scalar: NonZeroScalar) -> SecretKey {
        Self(scalar.into())
    }
}

impl From<&NonZeroScalar> for SecretKey {
    fn from(scalar: &NonZeroScalar) -> SecretKey {
        Self(scalar.into())
    }
}

impl From<SecretKey> for elliptic_curve::SecretKey<BignP256> {
    fn from(secret_key: SecretKey) -> Self {
        secret_key.0
    }
}

impl From<elliptic_curve::SecretKey<BignP256>> for SecretKey {
    fn from(secret_key: elliptic_curve::SecretKey<BignP256>) -> Self {
        Self(secret_key)
    }
}

impl Generate for SecretKey {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> core::result::Result<Self, R::Error> {
        elliptic_curve::SecretKey::try_generate_from_rng(rng).map(Self)
    }
}

#[cfg(feature = "pkcs8")]
impl AssociatedAlgorithmIdentifier for SecretKey {
    type Params = ObjectIdentifier;
    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = AlgorithmIdentifier {
        oid: ALGORITHM_OID,
        parameters: Some(BignP256::OID),
    };
}

#[cfg(feature = "pkcs8")]
impl TryFrom<pkcs8::PrivateKeyInfoRef<'_>> for SecretKey {
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        private_key_info
            .algorithm
            .assert_oids(ALGORITHM_OID, BignP256::OID)?;

        Self::from_slice(private_key_info.private_key.as_bytes())
            .map_err(|_| pkcs8::KeyError::Invalid.into())
    }
}

#[cfg(feature = "pem")]
impl FromStr for SecretKey {
    type Err = Error;
    fn from_str(s: &str) -> core::result::Result<Self, Error> {
        Self::from_pkcs8_pem(s).map_err(|_| Error)
    }
}

#[cfg(feature = "pkcs8")]
impl EncodePrivateKey for SecretKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        let algorithm_identifier = pkcs8::AlgorithmIdentifierRef {
            oid: ALGORITHM_OID,
            parameters: Some((&BignP256::OID).into()),
        };

        let ec_private_key = self.to_bytes();
        let pkcs8_key = pkcs8::PrivateKeyInfoRef::new(
            algorithm_identifier,
            OctetStringRef::new(&ec_private_key)?,
        );
        Ok(SecretDocument::encode_msg(&pkcs8_key)?)
    }
}
