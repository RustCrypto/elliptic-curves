//! Elliptic Curve Digital Signature Algorithm (ECDSA)

pub use super::BrainpoolP256r1;

/// ECDSA/brainpoolP256r1 signature (fixed-size)
pub type Signature = ecdsa::Signature<BrainpoolP256r1>;

/// ECDSA/brainpoolP256r1 signature (ASN.1 DER encoded)
pub type DerSignature = ecdsa::der::Signature<BrainpoolP256r1>;

impl ecdsa::EcdsaCurve for BrainpoolP256r1 {
    const NORMALIZE_S: bool = false;
}

#[cfg(feature = "sha256")]
impl ecdsa::hazmat::DigestPrimitive for BrainpoolP256r1 {
    type Digest = sha2::Sha256;
}
