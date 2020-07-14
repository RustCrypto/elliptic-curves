//! Elliptic Curve Digital Signature Algorithm (ECDSA)

pub use super::NistP256;

/// ECDSA/P-256 signature (fixed-size)
pub type Signature = ::ecdsa::Signature<NistP256>;

#[cfg(feature = "sha256")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha256")))]
impl ecdsa::hazmat::DigestPrimitive for NistP256 {
    type Digest = sha2::Sha256;
}
