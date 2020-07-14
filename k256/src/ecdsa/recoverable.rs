//! Ethereum-style "recoverable signatures"

use super::Signature;
use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
};
use ecdsa::{signature::Signature as _, Error};

#[cfg(docsrs)]
use crate::PublicKey;

/// Size of an Ethereum-style recoverable signature in bytes
pub const SIZE: usize = 65;

/// Ethereum-style "recoverable signatures" which allow for the recovery of
/// the signer's [`PublicKey`] from the signature itself.
///
/// This format consists of [`Signature`] followed by a 1-byte
/// [`RecoveryId`] (65-bytes total):
///
/// - `r`: 32-byte integer, big endian
/// - `s`: 32-byte integer, big endian
/// - `v`: 1-byte [`RecoveryId`]
#[derive(Copy, Clone)]
pub struct RecoverableSignature {
    bytes: [u8; SIZE],
}

impl RecoverableSignature {
    /// Get the [`RecoveryId`] for this signature
    pub fn recovery_id(self) -> RecoveryId {
        self.bytes[0].try_into().expect("invalid recovery ID")
    }
}

impl ecdsa::signature::Signature for RecoverableSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes.try_into()
    }
}

impl AsRef<[u8]> for RecoverableSignature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..]
    }
}

impl Debug for RecoverableSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoverableSignature {{ bytes: {:?}) }}", self.as_ref())
    }
}

// TODO(tarcieri): derive `Eq` after const generics are available
impl Eq for RecoverableSignature {}

// TODO(tarcieri): derive `PartialEq` after const generics are available
impl PartialEq for RecoverableSignature {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl TryFrom<&[u8]> for RecoverableSignature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == SIZE && RecoveryId::try_from(bytes[64]).is_ok() {
            let mut arr = [0u8; SIZE];
            arr.copy_from_slice(bytes);
            Ok(Self { bytes: arr })
        } else {
            Err(Error::new())
        }
    }
}

impl From<RecoverableSignature> for Signature {
    fn from(sig: RecoverableSignature) -> Signature {
        Signature::from_bytes(&sig.bytes[..64]).unwrap()
    }
}

/// Identifier used to compute a `PublicKey` from a [`RecoverableSignature`]
#[derive(Copy, Clone, Debug)]
pub struct RecoveryId(u8);

impl TryFrom<u8> for RecoveryId {
    type Error = Error;

    fn try_from(byte: u8) -> Result<Self, Error> {
        if byte < 4 {
            Ok(Self(byte))
        } else {
            Err(Error::new())
        }
    }
}

impl From<RecoveryId> for u8 {
    fn from(recovery_id: RecoveryId) -> u8 {
        recovery_id.0
    }
}
