//! General purpose Elliptic Curve Cryptography (ECC) support, including types
//! and traits for representing various elliptic curve forms, scalars, points,
//! and public/secret keys composed thereof.
//!
//! ## Minimum Supported Rust Version
//!
//! Rust **1.41** or higher.
//!
//! Minimum supported Rust version can be changed in the future, but it will be
//! done with a minor version bump.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png",
    html_root_url = "https://docs.rs/elliptic-curve/0.4.0"
)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "rand_core")]
pub use rand_core;

pub mod error;
pub mod secret_key;

pub use generic_array::{self, typenum::consts};
pub use subtle;

// TODO(tarcieri): other curve forms
#[cfg(feature = "weierstrass")]
#[cfg_attr(docsrs, doc(cfg(feature = "weierstrass")))]
pub mod weierstrass;

pub use self::{error::Error, secret_key::SecretKey};

/// Byte array containing a serialized scalar value (i.e. an integer)
pub type ScalarBytes<Size> = generic_array::GenericArray<u8, Size>;
