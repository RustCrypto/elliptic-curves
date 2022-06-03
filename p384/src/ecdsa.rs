//! Elliptic Curve Digital Signature Algorithm (ECDSA)
//!
//! This module contains support for computing and verifying ECDSA signatures.
//! To use it, you will need to enable one of the two following Cargo features:
//!
//! - `ecdsa-core`: provides only the [`Signature`] type (which represents an
//!   ECDSA/P-384 signature). Does not require the `arithmetic` feature. This is
//!   useful for 3rd-party crates which wish to use the `Signature` type for
//!   interoperability purposes (particularly in conjunction with the
//!   [`signature::Signer`] trait. Example use cases for this include other
//!   software implementations of ECDSA/P-384 and wrappers for cloud KMS
//!   services or hardware devices (HSM or crypto hardware wallet).
//! - `ecdsa`: provides `ecdsa-core` features plus the [`SigningKey`] and
//!   [`VerifyingKey`] types which natively implement ECDSA/P-384 signing and
//!   verification.
//!
//! ## Signing/Verification Example
//!
//! This example requires the `ecdsa` Cargo feature is enabled:
//!
//! ```
//! # #[cfg(feature = "ecdsa")]
//! # {
//! use p384::ecdsa::{signature::Signer, Signature, SigningKey};
//! use rand_core::OsRng; // requires 'getrandom' feature
//!
//! // Signing
//! let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
//! let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
//! let signature = signing_key.sign(message);
//!
//! // Verification
//! use p384::ecdsa::{signature::Verifier, VerifyingKey};
//!
//! let verifying_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`
//! assert!(verifying_key.verify(message, &signature).is_ok());
//! # }
//! ```

pub use ecdsa_core::signature::{self, Error};
#[cfg(feature = "ecdsa")]
use {
    crate::{AffinePoint, Scalar},
    ecdsa_core::hazmat::{SignPrimitive, VerifyPrimitive},
};

use super::NistP384;

/// ECDSA/P-384 signature (fixed-size)
pub type Signature = ecdsa_core::Signature<NistP384>;

/// ECDSA/P-384 signature (ASN.1 DER encoded)
pub type DerSignature = ecdsa_core::der::Signature<NistP384>;

/// ECDSA/P-384 signing key
#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub type SigningKey = ecdsa_core::SigningKey<NistP384>;

/// ECDSA/P-384 verification key (i.e. public key)
#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
pub type VerifyingKey = ecdsa_core::VerifyingKey<NistP384>;

#[cfg(feature = "sha384")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha384")))]
impl ecdsa_core::hazmat::DigestPrimitive for NistP384 {
    type Digest = sha2::Sha384;
}

#[cfg(feature = "ecdsa")]
impl SignPrimitive<NistP384> for Scalar {}

#[cfg(feature = "ecdsa")]
impl VerifyPrimitive<NistP384> for AffinePoint {}

#[cfg(all(test, feature = "ecdsa"))]
mod tests {
    use crate::{
        ecdsa::{signature::Signer, SigningKey},
        SecretKey,
    };
    use hex_literal::hex;

    // Test vector from RFC 6979 Appendix 2.6 (NIST P-384 + SHA-384)
    // <https://tools.ietf.org/html/rfc6979#appendix-A.2.6>
    #[test]
    fn rfc6979() {
        let x = &hex!("6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5");
        let signer = SigningKey::from_bytes(x).unwrap();
        let signature = signer.sign(b"sample");
        assert_eq!(
            signature.as_ref(),
            &hex!(
                "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46
                99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8"
            )[..]
        );
        let signature = signer.sign(b"test");
        assert_eq!(
            signature.as_ref(),
            &hex!(
                "8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023db
                ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e06a739f040649a667bf3b828246baa5a5"
            )[..]
        );
    }

    #[test]
    fn signing_secret_key_equivalent() {
        let raw_sk: [u8; 48] = [
            32, 52, 118, 9, 96, 116, 119, 172, 168, 251, 251, 197, 230, 33, 132, 85, 243, 25, 150,
            105, 121, 46, 248, 180, 102, 250, 168, 123, 220, 103, 121, 129, 68, 200, 72, 221, 3,
            102, 30, 237, 90, 198, 36, 97, 52, 12, 234, 150,
        ];

        let sigk = SigningKey::from_bytes(raw_sk.as_slice()).unwrap();
        let seck = SecretKey::from_be_bytes(raw_sk.as_slice()).unwrap();

        assert_eq!(sigk.to_bytes().as_slice(), &raw_sk);
        assert_eq!(sigk.to_bytes(), seck.to_be_bytes());
    }

    mod sign {
        use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, NistP384};
        ecdsa_core::new_signing_test!(NistP384, ECDSA_TEST_VECTORS);
    }

    mod verify {
        use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, NistP384};
        ecdsa_core::new_verification_test!(NistP384, ECDSA_TEST_VECTORS);
    }

    mod wycheproof {
        use crate::NistP384;
        ecdsa_core::new_wycheproof_test!(wycheproof, "wycheproof", NistP384);
    }
}
