//! Elliptic Curve Digital Signature Algorithm (ECDSA)
//!
//! This module contains support for computing and verifying ECDSA signatures.
//! To use it, you will need to enable one of the two following Cargo features:
//!
//! - `ecdsa-core`: provides only the [`Signature`] type (which represents an
//!   ECDSA/P-192 signature). Does not require the `arithmetic` feature. This is
//!   useful for 3rd-party crates which wish to use the `Signature` type for
//!   interoperability purposes. Example use cases for this include other
//!   software implementations of ECDSA/P-192 and wrappers for cloud KMS
//!   services or hardware devices (HSM or crypto hardware wallet).
//! - `ecdsa`: provides `ecdsa-core` features plus [`VerifyingKey`] types
//!   which natively implement ECDSA/P-192 verification.
//!
//! ## Verification only
//!
//! Following guidance from [NIST Special Publication 800-131A Revision 2]:
//! "Transitioning the Use of Cryptographic Algorithms and Key Lengths", this
//! crate only supports ECDSA verification, not signing.
//!
//! From Section 3: Digital Signatures:
//!
//! > <112 bits of security strength: ECDSA: len(n) < 224
//! >
//! > [...]
//! >
//! > Digital signature generation:
//! >
//! > Private-key lengths providing less than 112 bits of security **shall not** be used to
//! > generate digital signatures.
//!
//! [NIST Special Publication 800-131A Revision 2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf

pub use ecdsa_core::signature::{self, Error};

use super::NistP192;
use ecdsa_core::EcdsaCurve;

/// ECDSA/P-192 signature (fixed-size)
pub type Signature = ecdsa_core::Signature<NistP192>;

/// ECDSA/P-192 signature (ASN.1 DER encoded)
pub type DerSignature = ecdsa_core::der::Signature<NistP192>;

impl EcdsaCurve for NistP192 {
    const NORMALIZE_S: bool = false;
}

/// ECDSA/P-192 verification key (i.e. public key)
#[cfg(feature = "ecdsa")]
pub type VerifyingKey = ecdsa_core::VerifyingKey<NistP192>;

#[cfg(all(test, feature = "ecdsa"))]
mod tests {
    mod verify {
        use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, NistP192};
        ecdsa_core::new_verification_test!(NistP192, ECDSA_TEST_VECTORS);
    }
}
