//! Bign256 secret key.

use core::str::FromStr;
use der::{asn1::OctetStringRef, SecretDocument};

use elliptic_curve::{array::typenum::Unsigned, zeroize::Zeroizing, Error};
use pkcs8::{
    spki::{AlgorithmIdentifier, AssociatedAlgorithmIdentifier},
    AssociatedOid, DecodePrivateKey, EncodePrivateKey, ObjectIdentifier,
};

#[cfg(feature = "arithmetic")]
use crate::FieldBytes;
#[cfg(feature = "arithmetic")]
use crate::{elliptic_curve::rand_core::CryptoRngCore, BignP256, NonZeroScalar, Result};
use crate::{PublicKey, ScalarPrimitive, SecretKey, ALGORITHM_OID};

impl SecretKey {
    const MIN_SIZE: usize = 24;

    /// Generate a random [`SecretKey`].
    #[cfg(feature = "arithmetic")]
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            inner: NonZeroScalar::random(rng).into(),
        }
    }

    /// Borrow the inner secret [`elliptic_curve::ScalarPrimitive`] value.
    ///
    /// # ⚠️ Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    pub fn as_scalar_primitive(&self) -> &ScalarPrimitive {
        &self.inner
    }

    /// Get the secret [`elliptic_curve::NonZeroScalar`] value for this key.
    ///
    /// # ⚠️ Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    #[cfg(feature = "arithmetic")]
    pub fn to_nonzero_scalar(&self) -> NonZeroScalar {
        (*self).into()
    }

    /// Get the [`PublicKey`] which corresponds to this secret key
    #[cfg(feature = "arithmetic")]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_scalar(&self.to_nonzero_scalar())
    }

    /// Deserialize secret key from an encoded secret scalar.
    pub fn from_bytes(bytes: &FieldBytes) -> Result<Self> {
        let inner: ScalarPrimitive =
            Option::from(ScalarPrimitive::from_bytes(bytes)).ok_or(Error)?;

        if inner.is_zero().into() {
            return Err(Error);
        }

        Ok(Self { inner })
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
        if slice.len() == <BignP256 as elliptic_curve::Curve>::FieldBytesSize::USIZE {
            #[allow(deprecated)]
            Self::from_bytes(FieldBytes::from_slice(slice))
        } else if (Self::MIN_SIZE..<BignP256 as elliptic_curve::Curve>::FieldBytesSize::USIZE)
            .contains(&slice.len())
        {
            let mut bytes = Zeroizing::new(FieldBytes::default());
            let offset = <BignP256 as elliptic_curve::Curve>::FieldBytesSize::USIZE
                .saturating_sub(slice.len());
            bytes[offset..].copy_from_slice(slice);
            Self::from_bytes(&bytes)
        } else {
            Err(Error)
        }
    }

    /// Serialize raw secret scalar as a big endian integer.
    pub fn to_bytes(&self) -> FieldBytes {
        self.inner.to_bytes()
    }
}

impl From<SecretKey> for NonZeroScalar {
    fn from(secret_key: SecretKey) -> NonZeroScalar {
        secret_key.to_nonzero_scalar()
    }
}

#[cfg(feature = "arithmetic")]
impl From<NonZeroScalar> for SecretKey {
    fn from(scalar: NonZeroScalar) -> SecretKey {
        SecretKey::from(&scalar)
    }
}

#[cfg(feature = "arithmetic")]
impl From<&NonZeroScalar> for SecretKey {
    fn from(scalar: &NonZeroScalar) -> SecretKey {
        SecretKey {
            inner: scalar.into(),
        }
    }
}

impl AssociatedAlgorithmIdentifier for SecretKey {
    type Params = ObjectIdentifier;
    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = AlgorithmIdentifier {
        oid: ALGORITHM_OID,
        parameters: Some(BignP256::OID),
    };
}

impl TryFrom<pkcs8::PrivateKeyInfoRef<'_>> for SecretKey {
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        private_key_info
            .algorithm
            .assert_oids(ALGORITHM_OID, BignP256::OID)?;
        Self::from_slice(private_key_info.private_key.as_bytes())
            .map_err(|_| pkcs8::Error::KeyMalformed)
    }
}

#[cfg(feature = "pem")]
impl FromStr for SecretKey {
    type Err = Error;
    fn from_str(s: &str) -> core::result::Result<Self, Error> {
        Self::from_pkcs8_pem(s).map_err(|_| Error)
    }
}

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
