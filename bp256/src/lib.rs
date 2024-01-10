#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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

pub mod r1;
pub mod t1;

#[cfg(feature = "wip-arithmetic-do-not-use")]
mod arithmetic;

pub use crate::{r1::BrainpoolP256r1, t1::BrainpoolP256t1};
pub use elliptic_curve::{self, bigint::U256};

#[cfg(feature = "wip-arithmetic-do-not-use")]
pub use crate::arithmetic::scalar::Scalar;

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

use elliptic_curve::array::{typenum::U32, Array};

#[cfg(feature = "wip-arithmetic-do-not-use")]
pub(crate) use crate::arithmetic::field::FieldElement;

/// Byte representation of a base/scalar field element of a given curve.
pub type FieldBytes = Array<u8, U32>;

const ORDER_HEX: &str = "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7";
const ORDER: U256 = U256::from_be_hex(ORDER_HEX);
