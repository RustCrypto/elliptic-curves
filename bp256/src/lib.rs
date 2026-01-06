#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

//! ## Backends
//!
//! This crate has support for two different field arithmetic backends which can be selected using
//! `cfg(bp256_backend)`, e.g. to select the `bignum` backend:
//!
//! ```console
//! $ RUSTFLAGS='--cfg bp256_backend="bignum"' cargo test
//! ```
//!
//! Or it can be set through [`.cargo/config`][buildrustflags]:
//!
//! ```toml
//! [build]
//! rustflags = ['--cfg', 'bp256_backend="bignum"']
//! ```
//!
//! The available backends are:
//! - `bignum`: experimental backend provided by [crypto-bigint]. May offer better performance in
//!   some cases along with smaller code size, but might also have bugs.
//! - `fiat` (default): formally verified implementation synthesized by [fiat-crypto] which should
//!   be correct for all inputs (though there's a possibility of bugs in the code which glues to it)
//!
//! [buildrustflags]: https://doc.rust-lang.org/cargo/reference/config.html#buildrustflags
//! [crypto-bigint]: https://github.com/RustCrypto/crypto-bigint
//! [fiat-crypto]: https://github.com/mit-plv/fiat-crypto

pub mod r1;
pub mod t1;

#[cfg(feature = "arithmetic")]
mod arithmetic;

pub use crate::{r1::BrainpoolP256r1, t1::BrainpoolP256t1};
pub use elliptic_curve::{self, bigint::U256};

#[cfg(feature = "arithmetic")]
pub use crate::arithmetic::scalar::Scalar;

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

#[cfg(feature = "arithmetic")]
pub(crate) use crate::arithmetic::field::FieldElement;

use elliptic_curve::{
    array::{Array, typenum::U32},
    bigint::{ArrayEncoding, Odd},
};

/// Byte representation of a base/scalar field element of a given curve.
pub type FieldBytes = Array<u8, U32>;

const ORDER_HEX: &str = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
const ORDER: Odd<U256> = Odd::<U256>::from_be_hex(ORDER_HEX);

fn decode_field_bytes(field_bytes: &FieldBytes) -> U256 {
    U256::from_be_byte_array(*field_bytes)
}

fn encode_field_bytes(uint: &U256) -> FieldBytes {
    uint.to_be_byte_array()
}
