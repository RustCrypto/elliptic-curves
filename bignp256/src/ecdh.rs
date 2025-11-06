//! Elliptic Curve Diffie-Hellman (Ephemeral) Support.
//!
//! This module contains a high-level interface for performing ephemeral
//! Diffie-Hellman key exchanges using the bign-curve256v1 elliptic curve.
//!
//! # Usage
//!
//! This usage example is from the perspective of two participants in the
//! exchange, nicknamed "Alice" and "Bob".
//!
//! ```
//! use bignp256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
//! use rand::{rngs::OsRng, TryRngCore}; // requires 'os_rng' feature
//!
//! // Alice
//! let alice_secret = EphemeralSecret::random(&mut OsRng.unwrap_mut());
//! let alice_pk_bytes = EncodedPoint::from(alice_secret.public_key());
//!
//! // Bob
//! let bob_secret = EphemeralSecret::random(&mut OsRng.unwrap_mut());
//! let bob_pk_bytes = EncodedPoint::from(bob_secret.public_key());
//!
//! // Alice decodes Bob's serialized public key and computes a shared secret from it
//! let bob_public =
//!     PublicKey::from_encoded_point(bob_pk_bytes).expect("bob's public key is invalid!"); // In real usage, don't panic, handle this!
//!
//! let alice_shared = alice_secret.diffie_hellman(&bob_public.into());
//!
//! // Bob decodes Alice's serialized public key and computes the same shared secret
//! let alice_public =
//!     PublicKey::from_encoded_point(alice_pk_bytes).expect("alice's public key is invalid!"); // In real usage, don't panic, handle this!
//!
//! let bob_shared = bob_secret.diffie_hellman(&alice_public.into());
//!
//! // Both participants arrive on the same shared secret
//! assert_eq!(
//!     alice_shared.raw_secret_bytes(),
//!     bob_shared.raw_secret_bytes()
//! );
//! ```

pub use elliptic_curve::ecdh::diffie_hellman;

use crate::BignP256;

/// NIST P-256 Ephemeral Diffie-Hellman Secret.
pub type EphemeralSecret = elliptic_curve::ecdh::EphemeralSecret<BignP256>;

/// Shared secret value computed via ECDH key agreement.
pub type SharedSecret = elliptic_curve::ecdh::SharedSecret<BignP256>;
