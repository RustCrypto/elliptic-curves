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
//!     elliptic_curve::{Generate},
//!     SecretKey,
//! };
//! use rand_core::OsRng; // requires 'getrandom' feature
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
mod normalize;
#[cfg(feature = "ecdsa")]
mod signer;
#[cfg(feature = "ecdsa")]
mod verifier;

pub use ecdsa_core::signature::{self, Error};

#[cfg(feature = "ecdsa")]
pub use self::{signer::Signer, verifier::Verifier};

use crate::Secp256k1;

/// ECDSA/secp256k1 signature (fixed-size)
pub type Signature = ecdsa_core::Signature<Secp256k1>;

#[cfg(all(feature = "ecdsa", feature = "sha256"))]
impl ecdsa_core::hazmat::DigestPrimitive for Secp256k1 {
    type Digest = sha2::Sha256;
}
