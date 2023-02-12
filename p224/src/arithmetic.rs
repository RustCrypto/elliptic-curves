//! Pure Rust implementation of group operations on secp224r1.
//!
//! Curve parameters can be found in [NIST SP 800-186] § G.1.1: Curve P-384.
//!
//! [NIST SP 800-186]: https://csrc.nist.gov/publications/detail/sp/800-186/final

pub mod field;
pub mod scalar;
