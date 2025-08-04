//! Elliptic Curve Digital Signature Algorithm (ECDSA)
//!
//! This module contains support for computing and verifying ECDSA signatures.
//! To use it, you will need to enable the following Cargo feature: `ecdsa`
//!
//! ## Signing/Verification Example
//!
//! This example requires the `ecdsa` Cargo feature is enabled:
//!
//! ```
//! # #[cfg(feature = "ecdsa")]
//! # {
//! use bp256::{
//!     r1::ecdsa::{SigningKey, Signature, signature::Signer},
//! };
//! use rand_core::OsRng; // requires 'os_rng' feature
//!
//! // Signing
//! let signing_key = SigningKey::try_from_rng(&mut OsRng).unwrap(); // Serialize with `::to_bytes()`
//! let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
//! let signature: Signature = signing_key.sign(message);
//!
//! // Verification
//! use bp256::r1::ecdsa::{VerifyingKey, signature::Verifier};
//!
//! let verifying_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`
//! assert!(verifying_key.verify(message, &signature).is_ok());
//! # }
//! ```

pub use ecdsa::{
    RecoveryId,
    signature::{self, Error},
};

use super::BrainpoolP256r1;
use ecdsa::EcdsaCurve;

/// ECDSA/Brainpool-256r1 signature (fixed-size)
pub type Signature = ecdsa::Signature<BrainpoolP256r1>;

/// ECDSA/Brainpool-256r1 signature (ASN.1 DER encoded)
pub type DerSignature = ecdsa::der::Signature<BrainpoolP256r1>;

impl EcdsaCurve for BrainpoolP256r1 {
    const NORMALIZE_S: bool = false;
}

/// ECDSA/Brainpool-256r1 signing key
#[cfg(feature = "ecdsa")]
pub type SigningKey = ecdsa::SigningKey<BrainpoolP256r1>;

/// ECDSA/Brainpool-256r1 verification key (i.e. public key)
#[cfg(feature = "ecdsa")]
pub type VerifyingKey = ecdsa::VerifyingKey<BrainpoolP256r1>;

#[cfg(feature = "sha256")]
impl ecdsa::hazmat::DigestAlgorithm for BrainpoolP256r1 {
    type Digest = sha2::Sha256;
}

#[cfg(all(test, feature = "ecdsa"))]
mod tests {
    mod wycheproof {
        use crate::BrainpoolP256r1;
        ecdsa::new_wycheproof_test!(wycheproof, "wycheproof", BrainpoolP256r1);
    }
}
