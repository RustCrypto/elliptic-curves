//! Elliptic Curve Diffie-Hellman (Ephemeral) Support.

use crate::Secp256k1;

/// NIST P-256 Ephemeral Diffie-Hellman Secret.
pub type EphemeralSecret = elliptic_curve::ecdh::EphemeralSecret<Secp256k1>;

/// Shared secret value computed via ECDH key agreement.
pub type SharedSecret = elliptic_curve::ecdh::SharedSecret<Secp256k1>;
