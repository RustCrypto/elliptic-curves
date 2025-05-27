//! Elliptic Curve Digital Signature Algorithm (ECDSA)

pub use super::BrainpoolP512r1;

/// ECDSA/brainpoolP512r1 signature (fixed-size)
pub type Signature = ecdsa::Signature<BrainpoolP512r1>;

/// ECDSA/brainpoolP512r1 signature (ASN.1 DER encoded)
pub type DerSignature = ecdsa::der::Signature<BrainpoolP512r1>;

impl ecdsa::EcdsaCurve for BrainpoolP512r1 {
    const NORMALIZE_S: bool = false;
}

#[cfg(feature = "sha512")]
impl ecdsa::hazmat::DigestPrimitive for BrainpoolP512r1 {
    type Digest = sha2::Sha512;
}
