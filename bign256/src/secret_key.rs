//! Bign256 secret key.

use core::str::FromStr;
use der::{SecretDocument, asn1::OctetStringRef};

use elliptic_curve::{Error, array::typenum::Unsigned, zeroize::Zeroizing};
use pkcs8::{
    AssociatedOid, DecodePrivateKey, EncodePrivateKey, ObjectIdentifier,
    spki::{AlgorithmIdentifier, AssociatedAlgorithmIdentifier},
};

#[cfg(feature = "arithmetic")]
use crate::FieldBytes;
use crate::{ALGORITHM_OID, PublicKey, ScalarValue, SecretKey};
#[cfg(feature = "arithmetic")]
use crate::{
    BignP256, NonZeroScalar, Result,
    elliptic_curve::rand_core::{CryptoRng, TryCryptoRng},
};

impl SecretKey {
    const MIN_SIZE: usize = 24;

    /// Generate a random [`SecretKey`].
    #[cfg(feature = "arithmetic")]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self {
            inner: NonZeroScalar::random(rng).into(),
        }
    }

    /// Generate a random [`SecretKey`].
    #[cfg(feature = "arithmetic")]
    pub fn try_from_rng<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> core::result::Result<Self, R::Error> {
        Ok(Self {
            inner: NonZeroScalar::try_from_rng(rng)?.into(),
        })
    }

    /// Borrow the inner secret [`elliptic_curve::ScalarValue`] value.
    ///
    /// # ⚠️ Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    pub fn as_scalar_primitive(&self) -> &ScalarValue {
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
        let inner = ScalarValue::from_bytes(bytes).into_option().ok_or(Error)?;

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
