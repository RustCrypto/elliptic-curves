//! Elliptic Curve Digital Signature Algorithm (ECDSA)

pub use super::BrainpoolP384r1;

/// ECDSA/brainpoolP384r1 signature (fixed-size)
pub type Signature = ecdsa::Signature<BrainpoolP384r1>;

/// ECDSA/brainpoolP384r1 signature (ASN.1 DER encoded)
pub type Asn1Signature = ecdsa::der::Signature<BrainpoolP384r1>;

impl ecdsa::CheckSignatureBytes for BrainpoolP384r1 {}

#[cfg(feature = "sha384")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha384")))]
impl ecdsa::hazmat::DigestPrimitive for BrainpoolP384r1 {
    type Digest = sha2::Sha384;
}
