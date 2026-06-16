#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc = include_str!("../README.md")]

mod dev;
mod error;
mod macros;
mod monty;
mod traits;

pub use crate::{
    error::{Error, Result},
    monty::{MontyFieldBytes, MontyFieldElement, MontyFieldParams, compute_t},
    traits::PrimeFieldExt,
};
pub use array::typenum::consts;
pub use bigint;
pub use bigint::ByteOrder;
pub use bigint::hybrid_array as array;
pub use common;
pub use ff;
pub use rand_core;
pub use subtle;
pub use zeroize;
