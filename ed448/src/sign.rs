//! Ed448 digital signatures implementation
//!
//! # Example
//! Creating an ed448 signature.
//!
//! Generate a [`SigningKey`], which includes both the public and secret halves, using
//! a cryptographically secure pseudorandom number generator (CSPRNG). Next sign a message
//! to produce a [`Signature`]. Then verify the signature using the corresponding
//! [`VerifyingKey`].
//!
//! ```
//! use ed448_goldilocks_plus::*;
//! use rand_core::OsRng;
//!
//! let signing_key = SigningKey::generate(&mut OsRng);
//! let signature = signing_key.sign_raw(b"Hello, world!");
//! let verifying_key = signing_key.verifying_key();
//!
//! assert!(verifying_key.verify_raw(&signature, b"Hello, world!").is_ok());
//! ```
//!
//! This crate also supports using context specific strings when creating and verifying signatures.
//! In addition, it supports the PKCS#8 standard for encoding and decoding keys, or raw byte forms
//! using `to_bytes` and `from_bytes` methods. These store the [`SecretKey`] which is the prehash
//! seed of the [`SigningKey`].
//!
//! # PKCS#8 Key Encoding
//! PKCS#8 is a private key format with support for multiple algorithms. It can be encoded as
//! binary (DER) or text (PEM). Use the `pkcs8` feature to enable this option.
//!
//! # Using Serde
//! This crate supports serialization and deserialization using the `serde` if the preference
//! is to encode the keys as other formats. Use the `serde` feature to enable this option.
//!
//! # Using Signature
//! This crate supports signing using the traits defined in the `signature` crate like
//! - [`Signer`]
//! - [`DigestSigner`]
//! - [`PrehashSigner`]
//! - [`Verifier`]
//! - [`DigestVerifier`]
//!
//! The crate is re-exported as `crypto-signature` for use in other crates.
//!
//! # Other Features
//! Signing and verifying also supports custom digest and prehash algorithms.
//! Any algorith that implements [`PreHash`] and [`Digest`] can be used.
//! However, there are two implementations provided in this crate:
//!
//! - [`PreHasherXmd`] which supports any implementation of a fixed length digest like SHA3-512.
//! - [`PreHasherXof`] which supports any implementation of expandable output functions like SHAKE-256.
//!
//! # Example
//! This is an example of using the SHAKE-256 algorithm to sign and verify a message
//! which is the normal default anyway but performed explicitly.
//! ```
//! use ed448_goldilocks_plus::*;
//! use sha3::{Shake256, digest::Update};
//! use rand_core::OsRng;
//!
//! let msg = b"Hello World";
//! let signing_key = SigningKey::generate(&mut OsRng);
//! let signature = signing_key.sign_prehashed::<PreHasherXof<Shake256>>(
//!                        None,
//!                        Shake256::default().chain(msg).into(),
//!                    ).unwrap();
//! let verifying_key = signing_key.verifying_key();
//! assert!(verifying_key.verify_prehashed::<PreHasherXof<Shake256>>(
//!                    &signature, None, Shake256::default().chain(msg).into()).is_ok());
//! ```
mod context;
mod error;
mod expanded;
mod signature;
mod signing_key;
mod verifying_key;

pub use context::*;
pub use crypto_signature;
pub use error::*;
pub use pkcs8;
pub use signature::*;
pub use signing_key::*;
pub use verifying_key::*;

/// Length of a secret key in bytes
pub const SECRET_KEY_LENGTH: usize = 57;

/// Length of a public key in bytes
pub const PUBLIC_KEY_LENGTH: usize = 57;

/// Length of a signature in bytes
pub const SIGNATURE_LENGTH: usize = 114;

/// Constant string "SigEd448".
pub(crate) const HASH_HEAD: [u8; 8] = [0x53, 0x69, 0x67, 0x45, 0x64, 0x34, 0x34, 0x38];

#[cfg(feature = "pkcs8")]
/// The OID for Ed448 as defined in [RFC8410 §2]
pub const ALGORITHM_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.101.113");

#[cfg(feature = "pkcs8")]
/// The `AlgorithmIdentifier` for Ed448 as defined in [RFC8410 §2]
pub const ALGORITHM_ID: pkcs8::AlgorithmIdentifierRef<'static> = pkcs8::AlgorithmIdentifierRef {
    oid: ALGORITHM_OID,
    parameters: None,
};
