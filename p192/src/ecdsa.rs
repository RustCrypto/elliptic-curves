//! Elliptic Curve Digital Signature Algorithm (ECDSA)
//!
//! This module contains support for computing and verifying ECDSA signatures.
//! To use it, you will need to enable one of the two following Cargo features:
//!
//! - `ecdsa-core`: provides only the [`Signature`] type (which represents an
//!   ECDSA/P-192 signature). Does not require the `arithmetic` feature. This is
//!   useful for 3rd-party crates which wish to use the `Signature` type for
//!   interoperability purposes (particularly in conjunction with the
//!   [`signature::Signer`] trait. Example use cases for this include other
//!   software implementations of ECDSA/P-192 and wrappers for cloud KMS
//!   services or hardware devices (HSM or crypto hardware wallet).
//! - `ecdsa`: provides `ecdsa-core` features plus the [`SigningKey`] and
//!   [`VerifyingKey`] types which natively implement ECDSA/P-192 signing and
//!   verification.
//!
//! ## Signing/Verification Example
//!
//! This example requires the `ecdsa` Cargo feature is enabled:
//!
//! ```
//! # #[cfg(feature = "ecdsa")]
//! # {
//! use p192::ecdsa::{signature::Signer, Signature, SigningKey};
//! use rand_core::OsRng; // requires 'getrandom' feature
//!
//! // Signing
//! let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
//! let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
//! let signature: Signature = signing_key.sign(message);
//!
//! // Verification
//! use p192::ecdsa::{signature::Verifier, VerifyingKey};
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

use super::NistP192;

/// ECDSA/P-192 signature (fixed-size)
pub type Signature = ecdsa_core::Signature<NistP192>;

/// ECDSA/P-192 signature (ASN.1 DER encoded)
pub type DerSignature = ecdsa_core::der::Signature<NistP192>;

/// ECDSA/P-192 signing key
#[cfg(feature = "ecdsa")]
pub type SigningKey = ecdsa_core::SigningKey<NistP192>;

/// ECDSA/P-192 verification key (i.e. public key)
#[cfg(feature = "ecdsa")]
pub type VerifyingKey = ecdsa_core::VerifyingKey<NistP192>;

#[cfg(feature = "ecdsa")]
impl SignPrimitive<NistP192> for Scalar {}

#[cfg(feature = "ecdsa")]
impl VerifyPrimitive<NistP192> for AffinePoint {}

#[cfg(all(test, feature = "ecdsa"))]
mod tests {
    use crate::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
    use hex_literal::hex;
    use sha1::{Digest, Sha1};

    // Test vector from RFC 6979 Appendix 2.3 (NIST P-192 + SHA-1)
    // <https://tools.ietf.org/html/rfc6979#appendix-A.2.3>
    #[test]
    fn rfc6979() {
        let x = hex!("6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4");
        let signer = SigningKey::from_bytes(&x.into()).unwrap();

        let signature: Signature = signer.sign_prehash(&Sha1::digest(b"sample"));
        assert_eq!(
            signature.to_bytes().as_slice(),
            &hex!(
                "98C6BD12B23EAF5E2A2045132086BE3EB8EBD62ABF6698FF
                 57A22B07DEA9530F8DE9471B1DC6624472E8E2844BC25B64"
            )
        );

        let signature: Signature = signer.sign_prehash(&Sha1::digest(b"test"));
        assert_eq!(
            signature.to_bytes().as_slice(),
            &hex!(
                "0F2141A0EBBC44D2E1AF90A50EBCFCE5E197B3B7D4DE036D
                 EB18BC9E1F3D7387500CB99CF5F7C157070A8961E38700B7"
            )
        );
    }

    // mod sign {

    //     use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, NistP192};
    //     ecdsa_core::new_signing_test!(NistP192, ECDSA_TEST_VECTORS);
    // }

    // mod verify {
    //     use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, NistP192};
    //     ecdsa_core::new_verification_test!(NistP192, ECDSA_TEST_VECTORS);
    // }

    // mod wycheproof {
    //     use crate::NistP192;
    //     ecdsa_core::new_wycheproof_test!(wycheproof, "wycheproof", NistP192);
    // }
}
