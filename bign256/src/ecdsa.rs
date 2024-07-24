//! BignP256 Digital Signature Algorithm as defined in [STB 34.101.45-2013 § 7].
//!
//! ## Usage
//!
//! NOTE: requires the `dsa` crate feature enabled, and `rand_core` dependency
//! with `getrandom` feature enabled.
#![cfg_attr(feature = "std", doc = "```")]
#![cfg_attr(not(feature = "std"), doc = "```ignore")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use rand_core::OsRng; // requires 'getrandom` feature
//! use bign256::{
//!     ecdsa::{Signature, SigningKey, signature::Signer},
//!     SecretKey
//! };
//!
//! // Signing
//! let secret_key = SecretKey::random(&mut OsRng); // serialize with `::to_bytes()`
//! let signing_key = SigningKey::new(&secret_key)?;
//! let verifying_key_bytes = signing_key.verifying_key().to_bytes();
//! let message = b"test message";
//! let signature: Signature = signing_key.sign(message);
//!
//! // Verifying
//! use bign256::ecdsa::{VerifyingKey, signature::Verifier};
//!
//! let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)?;
//! verifying_key.verify(message, &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! [STB 34.101.45-2013 § 7]: https://apmi.bsu.by/assets/files/std/bign-spec294.pdf

#[cfg(feature = "arithmetic")]
mod signing;
#[cfg(feature = "arithmetic")]
mod verifying;

pub use signature;

#[cfg(feature = "arithmetic")]
pub use self::{signing::SigningKey, verifying::VerifyingKey};

use crate::{BignP256, FieldBytes, NonZeroScalar, Scalar};
use core::fmt::{self, Debug};
use elliptic_curve::{
    array::Array,
    consts::{U32, U48},
};
use signature::{Error, Result, SignatureEncoding};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// BignP256 signature serialized as bytes.
pub type SignatureBytes = [u8; Signature::BYTE_SIZE];

/// Primitive scalar type (works without the `arithmetic` feature).
type ScalarPrimitive = elliptic_curve::ScalarPrimitive<BignP256>;

const BELT_OID: [u8; 11] = [
    0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51,
];

#[derive(Copy, Clone, Eq, PartialEq)]
/// BignP256 Signature.
pub struct Signature {
    s0: ScalarPrimitive,
    s1: ScalarPrimitive,
}

impl Signature {
    /// Size of an encoded BignP256 signature in bytes.
    pub const BYTE_SIZE: usize = 48;

    /// Parse an BignP256 signature from a byte array.
    pub fn from_bytes(bytes: &SignatureBytes) -> Result<Self> {
        let (s0, s1) = bytes.split_at(Self::BYTE_SIZE / 3);
        let mut s0_bytes: Array<u8, U32> = Default::default();
        s0_bytes[..16].copy_from_slice(s0);

        let s0 = ScalarPrimitive::from_slice(&s0_bytes).map_err(|_| Error::new())?;
        let s1 = ScalarPrimitive::from_slice(s1).map_err(|_| Error::new())?;

        if s0.is_zero().into() || s1.is_zero().into() {
            return Err(Error::new());
        }

        Ok(Self { s0, s1 })
    }

    /// Parse an BignP256 signature from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        SignatureBytes::try_from(bytes)
            .map_err(|_| Error::new())?
            .try_into()
    }

    /// Create a [`Signature`] from the serialized `s0` and `s1` scalar values
    /// which comprise the signature.
    #[inline]
    pub fn from_scalars(s0: impl Into<FieldBytes>, s1: impl Into<FieldBytes>) -> Result<Self> {
        let s0 = &mut s0.into()[16..];
        let mut s1 = s1.into();

        s0.reverse();
        s1.reverse();

        let mut s: Array<u8, U48> = Default::default();
        s[..Self::BYTE_SIZE / 3].copy_from_slice(s0);
        s[Self::BYTE_SIZE / 3..Self::BYTE_SIZE].copy_from_slice(&s1);

        Self::try_from(s.as_slice())
    }

    /// Serialize this signature as bytes.
    pub fn to_bytes(&self) -> SignatureBytes {
        let mut ret = [0; Self::BYTE_SIZE];
        let (s0_bytes, s1_bytes) = ret.split_at_mut(Self::BYTE_SIZE / 3);
        s0_bytes.copy_from_slice(&self.s0.to_bytes()[..16]);
        s1_bytes.copy_from_slice(&self.s1.to_bytes());
        ret
    }

    /// Bytes for the `s0` component of a signature.
    pub fn s0_bytes(&self) -> FieldBytes {
        self.s0.to_bytes()
    }

    /// Bytes for the `s1` component of a signature.
    pub fn s1_bytes(&self) -> FieldBytes {
        self.s1.to_bytes()
    }

    /// Convert this signature into a byte vector.
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

#[cfg(feature = "arithmetic")]
impl Signature {
    /// Get the `s0` word component of this signature
    pub fn s0(&self) -> NonZeroScalar {
        let mut s0 = self.s0.to_bytes();
        s0.reverse();
        NonZeroScalar::new(Scalar::from_bytes(&s0).unwrap()).unwrap()
    }

    /// Get the `s1` word component of this signature
    pub fn s1(&self) -> NonZeroScalar {
        let mut s1 = self.s1.to_bytes();
        s1.reverse();
        NonZeroScalar::new(Scalar::from_bytes(&s1).unwrap()).unwrap()
    }

    /// Split the signature into its `s0` and `s1` scalars.
    pub fn split_scalars(&self) -> (NonZeroScalar, NonZeroScalar) {
        (self.s0(), self.s1())
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bignp256::dsa::Signature(")?;

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
