use core::fmt::{self, Display, Formatter};

#[cfg(feature = "std")]
use std::error::Error;

/// Signing errors
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SigningError {
    /// Prehashed context length is invalid
    PrehashedContextLength,
    /// Public key bytes are invalid
    InvalidPublicKeyBytes,
    /// Signature S component is invalid
    InvalidSignatureSComponent,
    /// Signature R component is invalid
    InvalidSignatureRComponent,
    /// Signature length is invalid
    InvalidSignatureLength,
    /// Signature verification failed
    Verify,
}

impl Display for SigningError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SigningError::PrehashedContextLength => {
                write!(f, "prehashed context length is invalid")
            }
            SigningError::InvalidPublicKeyBytes => write!(f, "public key bytes are invalid"),
            SigningError::InvalidSignatureSComponent => {
                write!(f, "signature S component is invalid")
            }
            SigningError::InvalidSignatureRComponent => {
                write!(f, "signature R component is invalid")
            }
            SigningError::InvalidSignatureLength => write!(f, "signature length is invalid"),
            SigningError::Verify => write!(f, "signature verification failed"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for SigningError {}

impl From<SigningError> for crypto_signature::Error {
    #[cfg(feature = "std")]
    fn from(err: SigningError) -> Self {
        crypto_signature::Error::from_source(err)
    }

    #[cfg(not(feature = "std"))]
    fn from(err: SigningError) -> Self {
        crypto_signature::Error::new()
    }
}
