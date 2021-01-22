//! Elliptic Curve Digital Signature Algorithm (ECDSA)

pub use crate::BrainpoolP384;

/// ECDSA/Brainpool P-384 signature (fixed-size)
pub type Signature = ecdsa::Signature<BrainpoolP384>;

/// ECDSA/Brainpool P-384 signature (ASN.1 DER encoded)
pub type Asn1Signature = ecdsa::der::Signature<BrainpoolP384>;

impl ecdsa::CheckSignatureBytes for BrainpoolP384 {}

#[cfg(feature = "sha384")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha384")))]
impl ecdsa::hazmat::DigestPrimitive for BrainpoolP384 {
    type Digest = sha2::Sha384;
}
