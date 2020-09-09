//! Elliptic Curve Diffie-Hellman (Ephemeral) Support.
//!
//! This module contains a high-level interface for performing ephemeral
//! Diffie-Hellman key exchanges using the secp256k1 elliptic curve.
//!
//! # Usage
//!
//! This usage example is from the perspective of two participants in the
//! exchange, nicknamed "Alice" and "Bob".
//!
//! ```
//! # #[cfg(feature = "ecdh")]
//! # {
//! use k256::{EncodedPoint, ecdh::EphemeralSecret};
//! use rand_core::OsRng; // requires 'getrandom' feature
//!
//! // Alice
//! let alice_secret = EphemeralSecret::random(&mut OsRng);
//! let alice_public = EncodedPoint::from(&alice_secret);
//!
//! // Bob
//! let bob_secret = EphemeralSecret::random(&mut OsRng);
//! let bob_public = EncodedPoint::from(&bob_secret);
//!
//! // Alice computes shared secret from Bob's public key
//! let alice_shared = alice_secret.diffie_hellman(&bob_public)
//!     .expect("bob's public key is invalid!");
//!
//! // Bob computes the same shared secret from Alice's public key
//! let bob_shared = bob_secret.diffie_hellman(&alice_public)
//!     .expect("alice's public key is invalid!");
//!
//! // Both participants arrive on the same shared secret
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//! # }
//! ```

use crate::Secp256k1;

/// NIST P-256 Ephemeral Diffie-Hellman Secret.
pub type EphemeralSecret = elliptic_curve::ecdh::EphemeralSecret<Secp256k1>;

/// Shared secret value computed via ECDH key agreement.
pub type SharedSecret = elliptic_curve::ecdh::SharedSecret<Secp256k1>;
