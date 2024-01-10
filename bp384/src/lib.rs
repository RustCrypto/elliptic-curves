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

pub use crate::{r1::BrainpoolP384r1, t1::BrainpoolP384t1};
pub use elliptic_curve::{self, bigint::U384};

#[cfg(feature = "wip-arithmetic-do-not-use")]
pub use crate::arithmetic::scalar::Scalar;

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

use elliptic_curve::array::{typenum::U48, Array};

#[cfg(feature = "wip-arithmetic-do-not-use")]
pub(crate) use crate::arithmetic::field::FieldElement;

/// Byte representation of a base/scalar field element of a given curve.
pub type FieldBytes = Array<u8, U48>;

const ORDER_HEX: &str = "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565";
const ORDER: U384 = U384::from_be_hex(ORDER_HEX);
