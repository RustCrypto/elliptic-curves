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
//! `cfg(bp512_backend)`, e.g. to select the `bigint` backend:
//!
//! ```console
//! $ RUSTFLAGS='--cfg bp512_backend="bigint"' cargo test
//! ```
//!
//! Or it can be set through [`.cargo/config`][buildrustflags]:
//!
//! ```toml
//! [build]
//! rustflags = ['--cfg', 'bp512_backend="bigint"']
//! ```
//!
//! The available backends are:
//! - `bigint`: experimental backend provided by [crypto-bigint]. May offer better performance in
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

pub use crate::{r1::BrainpoolP512r1, t1::BrainpoolP512t1};
pub use elliptic_curve::{self, bigint::U512};

#[cfg(feature = "arithmetic")]
pub use crate::arithmetic::scalar::Scalar;

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

#[cfg(feature = "arithmetic")]
pub(crate) use crate::arithmetic::field::FieldElement;

use elliptic_curve::{
    array::{Array, typenum::U64},
    bigint::Odd,
};

/// Byte representation of a base/scalar field element of a given curve.
pub type FieldBytes = Array<u8, U64>;

const ORDER_HEX: &str = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
const ORDER: Odd<U512> = Odd::<U512>::from_be_hex(ORDER_HEX);
