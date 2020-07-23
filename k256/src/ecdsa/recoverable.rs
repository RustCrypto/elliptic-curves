//! Ethereum-style "recoverable signatures"

use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug},
};
use ecdsa::{signature::Signature as _, Error};

#[cfg(feature = "arithmetic")]
use crate::arithmetic::{
    field::FieldElement, scalar::Scalar, AffinePoint, ProjectivePoint, CURVE_EQUATION_B,
};

#[cfg(feature = "arithmetic")]
use elliptic_curve::subtle::{Choice, ConditionallySelectable, CtOption};

#[cfg(any(feature = "arithmetic", docsrs))]
use crate::PublicKey;

#[cfg(all(feature = "arithmetic", feature = "sha256"))]
use sha2::{Digest, Sha256};

/// Size of an Ethereum-style recoverable signature in bytes
pub const SIZE: usize = 65;

/// Ethereum-style "recoverable signatures" which allow for the recovery of
/// the signer's [`PublicKey`] from the signature itself.
///
/// This format consists of [`Signature`] followed by a 1-byte recovery [`Id`]
/// (65-bytes total):
///
/// - `r`: 32-byte integer, big endian
/// - `s`: 32-byte integer, big endian
/// - `v`: 1-byte recovery [`Id`]
#[derive(Copy, Clone)]
pub struct Signature {
    bytes: [u8; SIZE],
}

impl Signature {
    /// Get the recovery [`Id`] for this signature
    pub fn recovery_id(self) -> Id {
        self.bytes[64].try_into().expect("invalid recovery ID")
    }

    /// Recover the [`PublicKey`] used to create the given signature
    #[cfg(all(feature = "arithmetic", feature = "sha256"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "arithmetic", feature = "sha256")))]
    #[allow(non_snake_case, clippy::many_single_char_names)]
    pub fn recover_pubkey(&self, msg: &[u8]) -> Result<PublicKey, Error> {
        let r = self.r()?;
        let s = self.s()?;
        let z = Scalar::from_digest(Sha256::new().chain(msg));
        let x = FieldElement::from_bytes(&r.to_bytes());

        let pk = x.and_then(|x| {
            let y_is_odd = Choice::from(self.recovery_id().0);
            let alpha = (x * &x * &x) + &CURVE_EQUATION_B;
            let beta = alpha.sqrt().unwrap();

            let y = FieldElement::conditional_select(
                &beta.negate(1),
                &beta,
                // beta.is_odd() == y_is_odd
                !(beta.normalize().is_odd() ^ y_is_odd),
            );

            let R = ProjectivePoint::from(AffinePoint {
                x,
                y: y.normalize(),
            });

            let r_inv = r.invert().unwrap();
            let u1 = -(r_inv * &z);
            let u2 = r_inv * &s;
            ((&ProjectivePoint::generator() * &u1) + &(R * &u2)).to_affine()
        });

        // TODO(tarcieri): replace with into conversion when available (see subtle#73)
        if pk.is_some().into() {
            Ok(pk.unwrap().to_pubkey(true))
        } else {
            Err(Error::new())
        }
    }

    /// Parse the `r` component of this signature to a [`Scalar`]
    #[cfg(feature = "arithmetic")]
    fn r(&self) -> Result<Scalar, Error> {
        let maybe_r = Scalar::from_bytes(self.bytes[..32].try_into().unwrap())
            .and_then(|r| CtOption::new(r, !r.is_zero()));

        // TODO(tarcieri): replace with into conversion when available (see subtle#73)
        if maybe_r.is_some().into() {
            Ok(maybe_r.unwrap())
        } else {
            Err(Error::new())
        }
    }

    /// Parse the `s` component of this signature to a [`Scalar`]
    #[cfg(feature = "arithmetic")]
    fn s(&self) -> Result<Scalar, Error> {
        let maybe_s = Scalar::from_bytes(self.bytes[32..64].try_into().unwrap())
            .and_then(|s| CtOption::new(s, !s.is_zero()));

        // TODO(tarcieri): replace with into conversion when available (see subtle#73)
        if maybe_s.is_some().into() {
            Ok(maybe_s.unwrap())
        } else {
            Err(Error::new())
        }
    }
}

impl ecdsa::signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
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

// TODO(tarcieri): derive `Eq` after const generics are available
impl Eq for Signature {}

// TODO(tarcieri): derive `PartialEq` after const generics are available
impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == SIZE && Id::try_from(bytes[64]).is_ok() {
            let mut arr = [0u8; SIZE];
            arr.copy_from_slice(bytes);
            Ok(Self { bytes: arr })
        } else {
            Err(Error::new())
        }
    }
}

impl From<Signature> for super::Signature {
    fn from(sig: Signature) -> Self {
        Self::from_bytes(&sig.bytes[..64]).unwrap()
    }
}

/// Identifier used to compute a [`PublicKey`] from a [`Signature`].
///
/// In practice these values are always either `0` or `1`, and indicate
/// whether or not the y-coordinate of the original [`PublicKey`] is odd.
///
/// While values `2` and `3` are also defined to capture whether `r`
/// overflowed the curve's order, this crate does *not* support them.
///
/// There is a vanishingly small chance of these values occurring outside
/// of contrived examples, so for simplicity's sake handling these values
/// is unsupported and will return an `Error` when parsing the `Id`.
#[derive(Copy, Clone, Debug)]
pub struct Id(u8);

impl TryFrom<u8> for Id {
    type Error = Error;

    fn try_from(byte: u8) -> Result<Self, Error> {
        match byte {
            0 | 1 => Ok(Self(byte)),
            _ => Err(Error::new()),
        }
    }
}

impl From<Id> for u8 {
    fn from(recovery_id: Id) -> u8 {
        recovery_id.0
    }
}

#[cfg(all(test, feature = "arithmetic", feature = "sha256"))]
mod tests {
    use super::Signature;
    use core::convert::TryFrom;
    use hex_literal::hex;

    /// Signature recovery test vectors
    struct TestVector {
        pk: [u8; 33],
        sig: [u8; 65],
        msg: &'static [u8],
    }

    const VECTORS: &[TestVector] = &[
        // Recovery ID 0
        TestVector {
            pk: hex!("021a7a569e91dbf60581509c7fc946d1003b60c7dee85299538db6353538d59574"),
            sig: hex!(
                "ce53abb3721bafc561408ce8ff99c909f7f0b18a2f788649d6470162ab1aa03239
                 71edc523a6d6453f3fb6128d318d9db1a5ff3386feb1047d9816e780039d5200"
            ),
            msg: b"example message",
        },
        // Recovery ID 1
        TestVector {
            pk: hex!("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"),
            sig: hex!(
                "46c05b6368a44b8810d79859441d819b8e7cdc8bfd371e35c53196f4bcacdb5135
                 c7facce2a97b95eacba8a586d87b7958aaf8368ab29cee481f76e871dbd9cb01"
            ),
            msg: b"example message",
        },
    ];

    #[test]
    fn public_key_recovery() {
        for vector in VECTORS {
            let sig = Signature::try_from(&vector.sig[..]).unwrap();
            let pk = sig.recover_pubkey(vector.msg).unwrap();
            assert_eq!(&vector.pk[..], pk.as_bytes());
        }
    }
}
