//! SM2 Digital Signature Algorithm (SM2DSA) as defined in [draft-shen-sm2-ecdsa § 5].
//!
//! ## Usage
//!
//! NOTE: requires the `dsa` crate feature enabled, and `rand_core` dependency
//! with `getrandom` feature enabled.
//!
#![cfg_attr(feature = "std", doc = "```")]
#![cfg_attr(not(feature = "std"), doc = "```ignore")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use rand_core::OsRng; // requires 'getrandom` feature
//! use sm2::{
//!     dsa::{Signature, SigningKey, signature::Signer},
//!     SecretKey
//! };
//!
//! // Signing
//! let secret_key = SecretKey::random(&mut OsRng); // serialize with `::to_bytes()`
//! let distid = "example@rustcrypto.org"; // distinguishing identifier
//! let signing_key = SigningKey::new(distid, &secret_key)?;
//! let verifying_key_bytes = signing_key.verifying_key().to_sec1_bytes();
//! let message = b"test message";
//! let signature: Signature = signing_key.sign(message);
//!
//! // Verifying
//! use sm2::dsa::{VerifyingKey, signature::Verifier};
//!
//! let verifying_key = VerifyingKey::from_sec1_bytes(distid, &verifying_key_bytes)?;
//! verifying_key.verify(message, &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! [draft-shen-sm2-ecdsa § 5]: https://datatracker.ietf.org/doc/html/draft-shen-sm2-ecdsa-02#section-5

#[cfg(feature = "arithmetic")]
mod signing;
#[cfg(feature = "arithmetic")]
mod verifying;

pub use signature;

#[cfg(feature = "arithmetic")]
pub use self::{signing::SigningKey, verifying::VerifyingKey};

use crate::{FieldBytes, NonZeroScalar, Sm2};
use core::fmt::{self, Debug};
use signature::{Error, Result, SignatureEncoding};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// SM2DSA signature serialized as bytes.
pub type SignatureBytes = [u8; Signature::BYTE_SIZE];

/// Primitive scalar type (works without the `arithmetic` feature).
type ScalarPrimitive = elliptic_curve::ScalarPrimitive<Sm2>;

/// SM2DSA signature.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Signature {
    r: ScalarPrimitive,
    s: ScalarPrimitive,
}

impl Signature {
    /// Size of an encoded SM2DSA signature in bytes.
    pub const BYTE_SIZE: usize = 64;

    /// Parse an SM2DSA signature from a byte array.
    pub fn from_bytes(bytes: &SignatureBytes) -> Result<Self> {
        let (r_bytes, s_bytes) = bytes.split_at(Self::BYTE_SIZE / 2);
        let r = ScalarPrimitive::from_slice(r_bytes).map_err(|_| Error::new())?;
        let s = ScalarPrimitive::from_slice(s_bytes).map_err(|_| Error::new())?;

        if r.is_zero().into() || s.is_zero().into() {
            return Err(Error::new());
        }

        Ok(Self { r, s })
    }

    /// Parse an SM2DSA signature from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        SignatureBytes::try_from(bytes)
            .map_err(|_| Error::new())?
            .try_into()
    }

    /// Create a [`Signature`] from the serialized `r` and `s` scalar values
    /// which comprise the signature.
    #[inline]
    pub fn from_scalars(r: impl Into<FieldBytes>, s: impl Into<FieldBytes>) -> Result<Self> {
        Self::try_from(r.into().concat(s.into()).as_slice())
    }

    /// Serialize this signature as bytes.
    pub fn to_bytes(&self) -> SignatureBytes {
        let mut ret = [0; Self::BYTE_SIZE];
        let (r_bytes, s_bytes) = ret.split_at_mut(Self::BYTE_SIZE / 2);
        r_bytes.copy_from_slice(&self.r.to_bytes());
        s_bytes.copy_from_slice(&self.s.to_bytes());
        ret
    }

    /// Bytes for the `R` component of a signature.
    pub fn r_bytes(&self) -> FieldBytes {
        self.r.to_bytes()
    }

    /// Bytes for the `s` component of a signature.
    pub fn s_bytes(&self) -> FieldBytes {
        self.s.to_bytes()
    }

    /// Convert this signature into a byte vector.
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

#[cfg(feature = "arithmetic")]
impl Signature {
    /// Get the `r` component of this signature
    pub fn r(&self) -> NonZeroScalar {
        NonZeroScalar::new(self.r.into()).unwrap()
    }

    /// Get the `s` component of this signature
    pub fn s(&self) -> NonZeroScalar {
        NonZeroScalar::new(self.s.into()).unwrap()
    }

    /// Split the signature into its `r` and `s` scalars.
    pub fn split_scalars(&self) -> (NonZeroScalar, NonZeroScalar) {
        (self.r(), self.s())
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sm2::dsa::Signature(")?;

        for byte in self.to_bytes() {
            write!(f, "{:02X}", byte)?;
        }

        write!(f, ")")
    }
}

impl From<Signature> for SignatureBytes {
    fn from(signature: Signature) -> SignatureBytes {
        signature.to_bytes()
    }
}

impl From<&Signature> for SignatureBytes {
    fn from(signature: &Signature) -> SignatureBytes {
        signature.to_bytes()
    }
}

impl SignatureEncoding for Signature {
    type Repr = SignatureBytes;

    fn to_bytes(&self) -> Self::Repr {
        self.into()
    }

    fn encoded_len(&self) -> usize {
        Self::BYTE_SIZE
    }
}

impl TryFrom<SignatureBytes> for Signature {
    type Error = Error;

    fn try_from(signature: SignatureBytes) -> Result<Signature> {
        Signature::from_bytes(&signature)
    }
}

impl TryFrom<&SignatureBytes> for Signature {
    type Error = Error;

    fn try_from(signature: &SignatureBytes) -> Result<Signature> {
        Signature::from_bytes(signature)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Signature> {
        Signature::from_slice(bytes)
    }
}
