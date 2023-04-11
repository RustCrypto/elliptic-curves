//! Pure Rust implementation of group operations on the SM2 elliptic curve.
//!
//! Curve parameters can be found in [draft-shen-sm2-ecdsa Appendix D]:
//! Recommended Parameters.
//!
//! [draft-shen-sm2-ecdsa Appendix D]: https://datatracker.ietf.org/doc/html/draft-shen-sm2-ecdsa-02#appendix-D

pub(crate) mod field;
pub(crate) mod scalar;
