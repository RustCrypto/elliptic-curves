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

#[cfg(feature = "arithmetic")]
mod arithmetic;

pub use crate::{r1::BrainpoolP512r1, t1::BrainpoolP512t1};
pub use elliptic_curve::{
    self,
    bigint::{ArrayEncoding, U512},
};

#[cfg(feature = "arithmetic")]
pub use crate::arithmetic::scalar::Scalar;

#[cfg(feature = "pkcs8")]
pub use elliptic_curve::pkcs8;

#[cfg(feature = "arithmetic")]
pub(crate) use crate::arithmetic::field::FieldElement;
use elliptic_curve::array::{Array, typenum::U64};

/// Byte representation of a base/scalar field element of a given curve.
pub type FieldBytes = Array<u8, U64>;

const ORDER_HEX: &str = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
const ORDER: U512 = U512::from_be_hex(ORDER_HEX);

fn decode_field_bytes(field_bytes: &FieldBytes) -> U512 {
    U512::from_be_byte_array(*field_bytes)
}

fn encode_field_bytes(uint: &U512) -> FieldBytes {
    uint.to_be_byte_array()
}
