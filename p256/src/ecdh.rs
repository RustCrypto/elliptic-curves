//! Elliptic Curve Diffie-Hellman (Ephemeral) Support.

use crate::NistP256;

/// NIST P-256 Ephemeral Diffie-Hellman Secret.
pub type EphemeralSecret = elliptic_curve::ecdh::EphemeralSecret<NistP256>;

/// Shared secret value computed via ECDH key agreement.
pub type SharedSecret = elliptic_curve::ecdh::SharedSecret<NistP256>;
