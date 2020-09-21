//! Elliptic Curve Digital Signature Algorithm (ECDSA).
//!
//! This module contains support for computing and verifying ECDSA signatures.
//! To use it, you will need to enable one of the two following Cargo features:
//!
//! - `ecdsa-core`: provides only the [`Signature`] type (which represents an
//!   ECDSA/secp256k1 signature). Does not require the `arithmetic` feature.
//!   This is useful for 3rd-party crates which wish to use the `Signature`
//!   type for interoperability purposes (particularly in conjunction with the
//!   [`signature::Signer`] trait). Example use cases for this include other
//!   software implementations of ECDSA/secp256k1 and wrappers for cloud KMS
//!   services or hardware devices (HSM or crypto hardware wallet).
//! - `ecdsa`: provides `ecdsa-core` features plus the [`SigningKey`] and
//!   [`VerifyKey`] types which natively implement ECDSA/secp256k1 signing and
//!   verification.
//!
//! Additionally, this crate contains support for computing ECDSA signatures
//! using either the SHA-256 (standard) or Keccak-256 (Ethereum) digest
//! functions, which are gated under the following Cargo features:
//!
//! - `sha256`: compute signatures using NIST's standard SHA-256 digest
//!   function. Unless you are computing signatures for Ethereum, this is
//!   almost certainly what you want.
//! - `keccak256`: compute signatures using the Keccak-256 digest function,
//!   an incompatible variant of the SHA-3 algorithm used exclusively by
//!   Ethereum.
//!
//! Most users of this library who want to sign/verify signatures will want to
//! enable the `ecdsa` and `sha256` Cargo features.
//!
//! ## Signing/Verification Example
//!
//! This example requires the `ecdsa` and `sha256` Cargo features are enabled:
//!
//! ```
//! # #[cfg(feature = "ecdsa")]
//! # {
//! use k256::{
//!     ecdsa::{SigningKey, Signature, signature::Signer},
//!     SecretKey,
//! };
//! use rand_core::OsRng; // requires 'getrandom' feature
//!
//! // Signing
//! let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
//! let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
//!
//! // Note: the signature type must be annotated or otherwise inferrable as
//! // `Signer` has many impls of the `Signer` trait (for both regular and
//! // recoverable signature types).
//! let signature: Signature = signing_key.sign(message);
//!
//! // Verification
//! use k256::{EncodedPoint, ecdsa::{VerifyKey, signature::Verifier}};
//!
//! let verify_key = VerifyKey::from(&signing_key); // Serialize with `::to_encoded_point()`
//! assert!(verify_key.verify(message, &signature).is_ok());
//! # }
//! ```

pub mod recoverable;

#[cfg(feature = "ecdsa")]
mod normalize;
#[cfg(feature = "ecdsa")]
mod sign;
#[cfg(feature = "ecdsa")]
mod verify;

pub use ecdsa_core::signature::{self, Error};

#[cfg(feature = "digest")]
pub use ecdsa_core::signature::digest;

#[cfg(feature = "ecdsa")]
pub use self::{sign::SigningKey, verify::VerifyKey};

use crate::Secp256k1;

#[cfg(feature = "ecdsa")]
use crate::NonZeroScalar;
#[cfg(feature = "ecdsa")]
use elliptic_curve::generic_array::GenericArray;

/// ECDSA/secp256k1 signature (fixed-size)
pub type Signature = ecdsa_core::Signature<Secp256k1>;

/// ECDSA/secp256k1 signature (ASN.1 DER encoded)
pub type Asn1Signature = ecdsa_core::asn1::Signature<Secp256k1>;

#[cfg(not(feature = "ecdsa"))]
impl ecdsa_core::CheckSignatureBytes for Secp256k1 {}

#[cfg(all(feature = "ecdsa", feature = "sha256"))]
impl ecdsa_core::hazmat::DigestPrimitive for Secp256k1 {
    type Digest = sha2::Sha256;
}

/// Validate that the scalars of an ECDSA signature are modulo the order
#[cfg(feature = "ecdsa")]
fn check_scalars(signature: &Signature) -> Result<(), Error> {
    let (r_bytes, s_bytes) = signature.as_ref().split_at(32);
    let r_valid = NonZeroScalar::from_repr(GenericArray::clone_from_slice(r_bytes)).is_some();
    let s_valid = NonZeroScalar::from_repr(GenericArray::clone_from_slice(s_bytes)).is_some();

    if r_valid && s_valid {
        Ok(())
    } else {
        Err(Error::new())
    }
}
