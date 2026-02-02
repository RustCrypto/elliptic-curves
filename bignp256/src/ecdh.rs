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
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires 'getrandom' feature is enabled
//!
//! use bignp256::{
//!     Sec1Point, PublicKey,
//!     ecdh::EphemeralSecret,
//!     elliptic_curve::Generate
//! };
//!
//! // Alice
//! let alice_secret = EphemeralSecret::generate();
//! let alice_pk_bytes = Sec1Point::from(alice_secret.public_key());
//!
//! // Bob
//! let bob_secret = EphemeralSecret::generate();
//! let bob_pk_bytes = Sec1Point::from(bob_secret.public_key());
//!
//! // Alice decodes Bob's serialized public key and computes a shared secret from it
//! let bob_public = PublicKey::from_sec1_point(bob_pk_bytes)?;
//! let alice_shared = alice_secret.diffie_hellman(&bob_public.into());
//!
//! // Bob decodes Alice's serialized public key and computes the same shared secret
//! let alice_public = PublicKey::from_sec1_point(alice_pk_bytes)?;
//! let bob_shared = bob_secret.diffie_hellman(&alice_public.into());
//!
//! // Both participants arrive on the same shared secret
//! assert_eq!(
//!     alice_shared.raw_secret_bytes(),
//!     bob_shared.raw_secret_bytes()
//! );
//! # Ok(())
//! # }
//! ```

pub use elliptic_curve::ecdh::diffie_hellman;

use crate::BignP256;

/// NIST P-256 Ephemeral Diffie-Hellman Secret.
pub type EphemeralSecret = elliptic_curve::ecdh::EphemeralSecret<BignP256>;

/// Shared secret value computed via ECDH key agreement.
pub type SharedSecret = elliptic_curve::ecdh::SharedSecret<BignP256>;
