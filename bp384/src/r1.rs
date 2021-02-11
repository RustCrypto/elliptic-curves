//! brainpoolP384r1 elliptic curve: verifiably pseudo-random variant

#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub mod ecdsa;

use elliptic_curve::consts::U32;

#[cfg(feature = "pkcs8")]
use crate::pkcs8;

/// brainpoolP384r1 elliptic curve: verifiably pseudo-random variant
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BrainpoolP384r1;

impl elliptic_curve::Curve for BrainpoolP384r1 {
    /// 384-bit (32-byte)
    type FieldSize = U32;
}

impl elliptic_curve::weierstrass::Curve for BrainpoolP384r1 {}

impl elliptic_curve::weierstrass::PointCompression for BrainpoolP384r1 {
    const COMPRESS_POINTS: bool = false;
}

#[cfg(feature = "pkcs8")]
impl elliptic_curve::AlgorithmParameters for BrainpoolP384r1 {
    const OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new(&[1, 3, 36, 3, 3, 2, 8, 1, 1, 11]);
}

/// brainpoolP384r1 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<BrainpoolP384r1>;

/// brainpoolP384r1 SEC1 encoded point.
pub type EncodedPoint = elliptic_curve::sec1::EncodedPoint<BrainpoolP384r1>;

/// brainpoolP384r1 secret key.
#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
pub type SecretKey = elliptic_curve::SecretKey<BrainpoolP384r1>;

/// Bytes containing a brainpoolP384r1 secret scalar.
#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
pub type SecretBytes = elliptic_curve::SecretBytes<BrainpoolP384r1>;

#[cfg(feature = "zeroize")]
impl elliptic_curve::SecretValue for BrainpoolP384r1 {
    type Secret = SecretBytes;

    /// Parse the secret value from bytes
    fn from_secret_bytes(bytes: &FieldBytes) -> Option<SecretBytes> {
        Some(bytes.clone().into())
    }
}

#[cfg(feature = "zeroize")]
impl elliptic_curve::sec1::ValidatePublicKey for BrainpoolP384r1 {}
