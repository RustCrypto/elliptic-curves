//! Elliptic Curve Digital Signature Algorithm (ECDSA)
//!
//! This module contains support for computing and verifying ECDSA signatures.
//! To use it, you will need to enable one of the two following Cargo features:
//!
//! - `ecdsa-core`: provides only the [`Signature`] type (which represents an
//!   ECDSA/P-224 signature). Does not require the `arithmetic` feature. This is
//!   useful for 3rd-party crates which wish to use the `Signature` type for
//!   interoperability purposes (particularly in conjunction with the
//!   [`signature::Signer`] trait. Example use cases for this include other
//!   software implementations of ECDSA/P-224 and wrappers for cloud KMS
//!   services or hardware devices (HSM or crypto hardware wallet).
//! - `ecdsa`: provides `ecdsa-core` features plus the [`SigningKey`] and
//!   [`VerifyingKey`] types which natively implement ECDSA/P-224 signing and
//!   verification.
//!
//! ## Signing/Verification Example
//!
//! This example requires the `ecdsa` Cargo feature is enabled:
//!
//! ```
//! # #[cfg(feature = "ecdsa")]
//! # {
//! use p224::ecdsa::{signature::Signer, Signature, SigningKey};
//! use rand_core::OsRng; // requires 'getrandom' feature
//!
//! // Signing
//! let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
//! let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
//! let signature: Signature = signing_key.sign(message);
//!
//! // Verification
//! use p224::ecdsa::{signature::Verifier, VerifyingKey};
//!
//! let verifying_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`
//! assert!(verifying_key.verify(message, &signature).is_ok());
//! # }
//! ```

pub use ecdsa_core::signature::{self, Error};

use super::NistP224;
use ecdsa_core::EcdsaCurve;

/// ECDSA/P-224 signature (fixed-size)
pub type Signature = ecdsa_core::Signature<NistP224>;

/// ECDSA/P-224 signature (ASN.1 DER encoded)
pub type DerSignature = ecdsa_core::der::Signature<NistP224>;

impl EcdsaCurve for NistP224 {
    const NORMALIZE_S: bool = false;
}

/// ECDSA/P-224 signing key
#[cfg(feature = "ecdsa")]
pub type SigningKey = ecdsa_core::SigningKey<NistP224>;

/// ECDSA/P-224 verification key (i.e. public key)
#[cfg(feature = "ecdsa")]
pub type VerifyingKey = ecdsa_core::VerifyingKey<NistP224>;

#[cfg(feature = "sha224")]
impl ecdsa_core::hazmat::DigestPrimitive for NistP224 {
    type Digest = sha2::Sha224;
}

#[cfg(all(test, feature = "ecdsa"))]
mod tests {
    use crate::ecdsa::{signature::Signer, Signature, SigningKey};
    use hex_literal::hex;

    // Test vector from RFC 6979 Appendix 2.4 (NIST P-224 + SHA-224)
    // <https://tools.ietf.org/html/rfc6979#appendix-A.2.4>
    #[test]
    fn rfc6979() {
        let x = hex!("F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1");
        let signer = SigningKey::from_bytes(&x.into()).unwrap();
        let signature: Signature = signer.sign(b"sample");
        assert_eq!(
            signature.to_bytes().as_slice(),
            &hex!(
                "1CDFE6662DDE1E4A1EC4CDEDF6A1F5A2FB7FBD9145C12113E6ABFD3E
                 A6694FD7718A21053F225D3F46197CA699D45006C06F871808F43EBC"
            )
        );

        let signature: Signature = signer.sign(b"test");
        assert_eq!(
            signature.to_bytes().as_slice(),
            &hex!(
                "C441CE8E261DED634E4CF84910E4C5D1D22C5CF3B732BB204DBEF019
                 902F42847A63BDC5F6046ADA114953120F99442D76510150F372A3F4"
            )
        );
    }

    mod sign {
        use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, NistP224};
        ecdsa_core::new_signing_test!(NistP224, ECDSA_TEST_VECTORS);
    }

    mod verify {
        use crate::{test_vectors::ecdsa::ECDSA_TEST_VECTORS, NistP224};
        ecdsa_core::new_verification_test!(NistP224, ECDSA_TEST_VECTORS);
    }

    mod wycheproof {
        use crate::NistP224;
        ecdsa_core::new_wycheproof_test!(wycheproof, "wycheproof", NistP224);
    }
}
