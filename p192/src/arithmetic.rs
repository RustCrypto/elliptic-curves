//! Pure Rust implementation of group operations on secp192r1.
//!
//! Curve parameters can be found in [FIPS 186-4] § D.1.2.1: Curve P-192.
//!
//! [FIPS 186-4]: https://csrc.nist.gov/publications/detail/fips/186/4/final

pub(crate) mod field;
pub(crate) mod scalar;
