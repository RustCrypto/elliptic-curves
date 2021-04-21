//! Elliptic Curve Digital Signature Algorithm (ECDSA)

pub use crate::NistP384;

/// ECDSA/P-384 signature (fixed-size)
pub type Signature = ecdsa::Signature<NistP384>;

/// ECDSA/P-384 signature (ASN.1 DER encoded)
pub type DerSignature = ecdsa::der::Signature<NistP384>;

#[cfg(feature = "sha384")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha384")))]
impl ecdsa::hazmat::DigestPrimitive for NistP384 {
    type Digest = sha2::Sha384;
}
