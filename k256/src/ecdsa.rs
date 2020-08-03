//! Elliptic Curve Digital Signature Algorithm (ECDSA).
//!
//! This module contains support for computing and verifying ECDSA signatures.
//! To use it, you will need to enable one of the two following Cargo features:
//!
//! - `ecdsa-core`: provides only the [`Signature`] type (which represents an
//!   ECDSA/secp256k1 signature). Does not require the `arithmetic` feature.
//!   This is useful for 3rd-party crates which wish to use the `Signature`
//!   type for interoperability purposes (particularly in conjunction with the
//!   [`signature::Signer`] trait. Example use cases for this include other
//!   software implementations of ECDSA/secp256k1 and wrappers for cloud KMS
//!   services or hardware devices (HSM or crypto hardware wallet).
//! - `ecdsa`: provides the [`Signature`], [`Signer`], and [`Verifier`] types
//!   which natively implement ECDSA/secp256k1 signing and verification.
//!
//! ## Signing/Verification Example
//!
//! This example requires the `ecdsa` Cargo feature is enabled:
//!
//! ```
//! # #[cfg(feature = "ecdsa")]
//! # {
//! use k256::{
//!     ecdsa::{Signer, Signature, signature::RandomizedSigner},
//!     elliptic_curve::{Generate, rand_core::OsRng},
//!     SecretKey,
//! };
//!
//! // Signing
//! let secret_key = SecretKey::generate(&mut OsRng);
//! let signer = Signer::new(&secret_key).expect("secret key invalid");
//! let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
//!
//! // Note: the signature type must be annotated or otherwise inferrable as
//! // `Signer` has many impls of the `RandomizedSigner` trait (for both
//! // regular and recoverable signature types).
//! let signature: Signature = signer.sign_with_rng(&mut OsRng, message);
//!
//! // Verification
//! use k256::{PublicKey, ecdsa::{Verifier, signature::Verifier as _}};
//!
//! let public_key = PublicKey::from_secret_key(&secret_key, true).expect("secret key invalid");
//! let verifier = Verifier::new(&public_key).expect("public key invalid");
//!
//! assert!(verifier.verify(message, &signature).is_ok());
//! # }
//! ```

pub mod recoverable;

#[cfg(feature = "ecdsa")]
mod signer;
#[cfg(feature = "ecdsa")]
mod verifier;

pub use ecdsa_core::signature::{self, Error};

#[cfg(feature = "ecdsa")]
pub use self::{signer::Signer, verifier::Verifier};

use crate::Secp256k1;

#[cfg(feature = "ecdsa")]
use crate::{elliptic_curve::subtle::ConditionallySelectable, Scalar};

/// ECDSA/secp256k1 signature (fixed-size)
pub type Signature = ecdsa_core::Signature<Secp256k1>;

#[cfg(feature = "sha256")]
#[cfg_attr(docsrs, doc(cfg(feature = "sha256")))]
impl ecdsa_core::hazmat::DigestPrimitive for Secp256k1 {
    type Digest = sha2::Sha256;
}

#[cfg(feature = "ecdsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "ecdsa")))]
/// Normalize signature into "low S" form as described in
/// [BIP 0062: Dealing with Malleability][1].
///
/// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
pub fn normalize_s(signature: &Signature) -> Result<Signature, Error> {
    use core::convert::TryInto;
    let s_option = Scalar::from_bytes(signature.as_ref()[32..].try_into().unwrap());

    // Not constant time, but we're operating on public values
    let s = if s_option.is_some().into() {
        s_option.unwrap()
    } else {
        return Err(Error::new());
    };

    // Negate `s` if it's within the upper half of the modulus
    let s_neg = -s;
    let low_s = Scalar::conditional_select(&s, &s_neg, s.is_high());

    Ok(Signature::from_scalars(
        signature.r(),
        &low_s.to_bytes().into(),
    ))
}

#[cfg(all(test, feature = "ecdsa"))]
mod tests {
    use super::{normalize_s, Signature};
    use ecdsa_core::signature::Signature as _;

    // Test vectors generated using rust-secp256k1
    #[test]
    #[rustfmt::skip]
    fn normalize_s_high() {
        let sig_hi = Signature::from_bytes(&[
            0x20, 0xc0, 0x1a, 0x91, 0x0e, 0xbb, 0x26, 0x10,
            0xaf, 0x2d, 0x76, 0x3f, 0xa0, 0x9b, 0x3b, 0x30,
            0x92, 0x3c, 0x8e, 0x40, 0x8b, 0x11, 0xdf, 0x2c,
            0x61, 0xad, 0x76, 0xd9, 0x70, 0xa2, 0xf1, 0xbc,
            0xee, 0x2f, 0x11, 0xef, 0x8c, 0xb0, 0x0a, 0x49,
            0x61, 0x7d, 0x13, 0x57, 0xf4, 0xd5, 0x56, 0x41,
            0x09, 0x0a, 0x48, 0xf2, 0x01, 0xe9, 0xb9, 0x59,
            0xc4, 0x8f, 0x6f, 0x6b, 0xec, 0x6f, 0x93, 0x8f,
        ]).unwrap();

        let sig_lo = Signature::from_bytes(&[
            0x20, 0xc0, 0x1a, 0x91, 0x0e, 0xbb, 0x26, 0x10,
            0xaf, 0x2d, 0x76, 0x3f, 0xa0, 0x9b, 0x3b, 0x30,
            0x92, 0x3c, 0x8e, 0x40, 0x8b, 0x11, 0xdf, 0x2c,
            0x61, 0xad, 0x76, 0xd9, 0x70, 0xa2, 0xf1, 0xbc,
            0x11, 0xd0, 0xee, 0x10, 0x73, 0x4f, 0xf5, 0xb6,
            0x9e, 0x82, 0xec, 0xa8, 0x0b, 0x2a, 0xa9, 0xbd,
            0xb1, 0xa4, 0x93, 0xf4, 0xad, 0x5e, 0xe6, 0xe1,
            0xfb, 0x42, 0xef, 0x20, 0xe3, 0xc6, 0xad, 0xb2,
        ]).unwrap();

        let sig_normalized = normalize_s(&sig_hi).unwrap();
        assert_eq!(sig_lo, sig_normalized);
    }

    #[test]
    fn normalize_s_low() {
        #[rustfmt::skip]
        let sig = Signature::from_bytes(&[
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]).unwrap();

        let sig_normalized = normalize_s(&sig).unwrap();
        assert_eq!(sig, sig_normalized);
    }
}
