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

pub mod r1;
pub mod t1;

pub use crate::{r1::BrainpoolP256r1, t1::BrainpoolP256t1};
pub use elliptic_curve::{self, bigint::U256};

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;
