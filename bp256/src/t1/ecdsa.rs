//! Elliptic Curve Digital Signature Algorithm (ECDSA)

pub use super::BrainpoolP256t1;

/// ECDSA/brainpoolP256t1 signature (fixed-size)
pub type Signature = ecdsa::Signature<BrainpoolP256t1>;

/// ECDSA/brainpoolP256t1 signature (ASN.1 DER encoded)
pub type Asn1Signature = ecdsa::der::Signature<BrainpoolP256t1>;

impl ecdsa::CheckSignatureBytes for BrainpoolP256t1 {}

#[cfg(feature = "sha256")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha256")))]
impl ecdsa::hazmat::DigestPrimitive for BrainpoolP256t1 {
    type Digest = sha2::Sha256;
}
