//! Ethereum-style "recoverable signatures".
//!
//! These signatures include an additional [`Id`] field which allows for
//! recovery of the [`VerifyingKey`] which can be used to verify them.
//!
//! This is helpful in cases where a hash/fingerprint of a [`VerifyingKey`]
//! for a given signature in known in advance.
//!
//! ## Signing/Recovery Example
//!
//! NOTE: make sure to enable both the `ecdsa` and `sha256` features of
//! this crate for the example to work.
//!
//! ```
//! # #[cfg(all(feature = "ecdsa", feature = "sha256"))]
//! # {
//! use p256::{
//!     ecdsa::{SigningKey, recoverable, signature::Signer},
//!     EncodedPoint
//! };
//! use rand_core::OsRng; // requires 'getrandom' feature
//!
//! // Signing
//! let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
//! let verifying_key = signing_key.verifying_key();
//! let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
//!
//! // Note: the signature type must be annotated or otherwise inferrable as
//! // `Signer` has many impls of the `Signer` trait (for both regular and
//! // recoverable signature types).
//! let signature: recoverable::Signature = signing_key.sign(message);
//! let recovered_key = signature.recover_verifying_key(message).expect("couldn't recover pubkey");
//!
//! assert_eq!(&verifying_key, &recovered_key);
//! # }
//! ```

use core::fmt::{self, Debug};
use ecdsa_core::{signature::Signature as _, Error, Result};
use elliptic_curve::subtle::Choice;

#[cfg(feature = "ecdsa")]
use crate::{
    ecdsa::{
        signature::digest::{Digest, FixedOutput},
        verify::VerifyingKey,
    },
    elliptic_curve::{
        bigint::U256,
        consts::U32,
        ops::{Invert, LinearCombination, Reduce},
        DecompressPoint,
    },
    AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar,
};

#[cfg(feature = "sha256")]
use sha2::Sha256;

/// Size of an Ethereum-style recoverable signature in bytes
pub const SIZE: usize = 65;

/// Ethereum-style "recoverable signatures" which allow for the recovery of
/// the signer's [`VerifyingKey`] from the signature itself.
///
/// This format consists of [`Signature`] followed by a 1-byte recovery [`Id`]
/// (65-bytes total):
///
/// - `r`: 32-byte integer, big endian
/// - `s`: 32-byte integer, big endian
/// - `v`: 1-byte recovery [`Id`]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Signature {
    bytes: [u8; SIZE],
}

impl Signature {
    /// Create a new recoverable ECDSA/P-256 signature from a regular
    /// fixed-size signature and an associated recovery [`Id`].
    ///
    /// This is an "unchecked" conversion and assumes the provided [`Id`]
    /// is valid for this signature.
    pub fn new(signature: &super::Signature, recovery_id: Id) -> Result<Self> {
        let mut bytes = [0u8; SIZE];
        bytes[..64].copy_from_slice(signature.as_ref());
        bytes[64] = recovery_id.0;
        Ok(Self { bytes })
    }

    /// Get the recovery [`Id`] for this signature
    pub fn recovery_id(self) -> Id {
        self.bytes[64].try_into().expect("invalid recovery ID")
    }

    /// Given a public key, message, and signature, use trial recovery
    /// to determine if a suitable recovery ID exists, or return an error
    /// otherwise.
    ///
    /// Assumes Sha256 as the message digest function. Use
    /// [`Signature::from_digest_trial_recovery`] to support other
    ///digest functions.
    #[cfg(all(feature = "ecdsa", feature = "sha256"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha256")))]
    pub fn from_trial_recovery(
        public_key: &VerifyingKey,
        msg: &[u8],
        signature: &super::Signature,
    ) -> Result<Self> {
        Self::from_digest_trial_recovery(public_key, Sha256::new_with_prefix(msg), signature)
    }

    /// Given a public key, message digest, and signature, use trial recovery
    /// to determine if a suitable recovery ID exists, or return an error
    /// otherwise.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    pub fn from_digest_trial_recovery<D>(
        public_key: &VerifyingKey,
        digest: D,
        signature: &super::Signature,
    ) -> Result<Self>
    where
        D: Clone + Digest + FixedOutput<OutputSize = U32>,
    {
        use ecdsa_core::signature::DigestVerifier;

        let signature = signature.normalize_s().unwrap_or(*signature);

        for recovery_id in 0..=1 {
            if let Ok(recoverable_signature) = Signature::new(&signature, Id(recovery_id)) {
                if let Ok(recovered_key) =
                    recoverable_signature.recover_verifying_key_from_digest(digest.clone())
                {
                    if public_key == &recovered_key
                        && public_key.verify_digest(digest.clone(), &signature).is_ok()
                    {
                        return Ok(recoverable_signature);
                    }
                }
            }
        }

        Err(Error::new())
    }

    /// Recover the public key used to create the given signature as a
    /// [`VerifyingKey`].
    #[cfg(all(feature = "ecdsa", feature = "sha256"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "sha256")))]
    pub fn recover_verifying_key(&self, msg: &[u8]) -> Result<VerifyingKey> {
        self.recover_verifying_key_from_digest(Sha256::new_with_prefix(msg))
    }

    /// Recover the public key used to create the given signature as a
    /// [`VerifyingKey`] from the provided precomputed [`Digest`].
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    pub fn recover_verifying_key_from_digest<D>(&self, msg_digest: D) -> Result<VerifyingKey>
    where
        D: Digest<OutputSize = U32>,
    {
        self.recover_verifying_key_from_digest_bytes(&msg_digest.finalize())
    }

    /// Recover the public key used to create the given signature as a
    /// [`VerifyingKey`] from the raw bytes of a message digest.
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    #[allow(non_snake_case, clippy::many_single_char_names)]
    pub fn recover_verifying_key_from_digest_bytes(
        &self,
        digest_bytes: &FieldBytes,
    ) -> Result<VerifyingKey> {
        let r = self.r();
        let s = self.s();
        let z = <Scalar as Reduce<U256>>::from_be_bytes_reduced(*digest_bytes);
        let R = AffinePoint::decompress(&r.to_bytes(), self.recovery_id().is_y_odd());

        if R.is_none().into() {
            return Err(Error::new());
        }

        let R = ProjectivePoint::from(R.unwrap());
        let r_inv = *r.invert();
        let u1 = -(r_inv * z);
        let u2 = r_inv * *s;
        let pk = ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, &u1, &R, &u2);

        // TODO(tarcieri): ensure the signature verifies?
        VerifyingKey::try_from(pk)
    }

    /// Parse the `r` component of this signature to a [`NonZeroScalar`]
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    pub fn r(&self) -> NonZeroScalar {
        NonZeroScalar::try_from(&self.bytes[..32])
            .expect("r-component ensured valid in constructor")
    }

    /// Parse the `s` component of this signature to a [`NonZeroScalar`]
    #[cfg(feature = "ecdsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
    pub fn s(&self) -> NonZeroScalar {
        NonZeroScalar::try_from(&self.bytes[32..64])
            .expect("s-component ensured valid in constructor")
    }
}

impl ecdsa_core::signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bytes.try_into()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..]
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoverableSignature {{ bytes: {:?}) }}", self.as_ref())
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIZE {
            return Err(Error::new());
        }

        let signature = super::Signature::try_from(&bytes[..64])?;
        let recovery_id = Id::try_from(bytes[64])?;
        Self::new(&signature, recovery_id)
    }
}

impl From<Signature> for super::Signature {
    fn from(sig: Signature) -> Self {
        Self::from_bytes(&sig.bytes[..64]).unwrap()
    }
}

#[cfg(feature = "sha256")]
impl ecdsa_core::signature::PrehashSignature for Signature {
    type Digest = Sha256;
}

/// Identifier used to compute a [`VerifyingKey`] from a [`Signature`].
///
/// In practice these values are always either `0` or `1`, and indicate
/// whether or not the y-coordinate of the original [`VerifyingKey`] is odd.
///
/// While values `2` and `3` are also defined to capture whether `r`
/// overflowed the curve's order, this crate does *not* support them.
///
/// There is a vanishingly small chance of these values occurring outside
/// of contrived examples, so for simplicity's sake handling these values
/// is unsupported and will return an `Error` when parsing the `Id`.
#[derive(Copy, Clone, Debug)]
pub struct Id(pub(super) u8);

impl Id {
    /// Create a new [`Id`] from the given byte value
    pub fn new(byte: u8) -> Result<Self> {
        match byte {
            0 | 1 => Ok(Self(byte)),
            _ => Err(Error::new()),
        }
    }

    /// Is `y` odd?
    fn is_y_odd(self) -> Choice {
        self.0.into()
    }
}

impl TryFrom<u8> for Id {
    type Error = Error;

    fn try_from(byte: u8) -> Result<Self> {
        Self::new(byte)
    }
}

impl From<Id> for u8 {
    fn from(recovery_id: Id) -> u8 {
        recovery_id.0
    }
}

impl TryFrom<ecdsa_core::RecoveryId> for Id {
    type Error = Error;

    fn try_from(id: ecdsa_core::RecoveryId) -> Result<Id> {
        if id.is_x_reduced() {
            Err(Error::new())
        } else if id.is_y_odd() {
            Ok(Id(1))
        } else {
            Ok(Id(0))
        }
    }
}

impl From<Id> for ecdsa_core::RecoveryId {
    fn from(id: Id) -> ecdsa_core::RecoveryId {
        ecdsa_core::RecoveryId::new(id.is_y_odd().into(), false)
    }
}

#[cfg(all(test, feature = "ecdsa", feature = "sha256"))]
mod tests {
    use super::Signature;
    use crate::{ecdsa::sign::SigningKey, EncodedPoint};
    use ecdsa_core::signature::Signer;
    use hex_literal::hex;
    use sha2::{Digest, Sha256};

    /// Signature recovery test vectors
    struct RecoveryTestVector {
        pk: [u8; 33],
        sig: [u8; 65],
        msg: &'static [u8],
    }

    const RECOVERY_TEST_VECTORS: &[RecoveryTestVector] = &[
        // Recovery ID 0
        RecoveryTestVector {
            pk: hex!("02c156afee1ce52ef83a0dd168c1144eb20008697e6664fa132ba23c128cce8055"),
            sig: hex!(
                "45fef169243c0163c2e86c864a37973c56733a152303626eafe971b5524e8d4edbd3353771de5a5ef931b53736a12ed6e65fd41a193ca87f165d852f888a03c200"
            ),
            msg: b"example message",
        },
        // Recovery ID 1
        RecoveryTestVector {
            pk: hex!("02c156afee1ce52ef83a0dd168c1144eb20008697e6664fa132ba23c128cce8055"),
            sig: hex!(
                "213304ff146105f365feb04ec3aa20f4bb658e4c0c4e11d4820836fa793f173b0479c7332ac3174a5175d9f87df0b28b9f117477288de8f5ece48f9f07827b8601"
            ),
            msg: b"example message 2",
        },
    ];

    #[test]
    fn public_key_recovery() {
        for vector in RECOVERY_TEST_VECTORS {
            let sig = Signature::try_from(&vector.sig[..]).unwrap();
            let prehash = Sha256::new_with_prefix(vector.msg);
            let pk = sig.recover_verifying_key_from_digest(prehash).unwrap();
            assert_eq!(&vector.pk[..], EncodedPoint::from(&pk).as_bytes());
        }
    }

    /// Ensures RFC6979 is implemented in the same way as other Ethereum
    /// libraries, using HMAC-DRBG-SHA-256 for RFC6979, and Sha256 for
    /// hashing the message.
    ///
    /// Test vectors adapted from:
    /// <https://github.com/gakonst/ethers-rs/blob/ba00f549/ethers-signers/src/wallet/private_key.rs#L197>
    #[test]
    fn signing_rfc6979() {
        let signing_key = SigningKey::from_bytes(&hex!(
            "f67b03b2c6e4bf86cce50298dbce351b332c3be65ced9f312b6d9ffc3de6b04f"
        ))
        .unwrap();

        let msg = hex!(
            "e9808504e3b29200831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca0080018080"
        );

        let sig: Signature = signing_key.sign(&msg);
        assert_eq!(sig.as_ref(), &hex!("5da79ba879954cc8a25e8e48eae031c856adb2d385cdc6ac75c890fff62df5f33938d7da87e3175d9d00e90671b43a6c7e9327ac5be03ed8f6b195cc44a8089d00"));
    }
}
