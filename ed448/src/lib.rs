//! This crate provides a pure Rust implementation of Curve448, Edwards, Decaf, and Ristretto.
//! It is intended to be portable, fast, and safe.
//!
//! # Usage
//! ```
//! use ed448_goldilocks_plus::{EdwardsPoint, CompressedEdwardsY, Scalar, elliptic_curve::hash2curve::ExpandMsgXof, sha3::Shake256};
//! use rand_core::OsRng;
//!
//! let secret_key = Scalar::TWO;
//! let public_key = EdwardsPoint::GENERATOR * &secret_key;
//!
//! assert_eq!(public_key, EdwardsPoint::GENERATOR + EdwardsPoint::GENERATOR);
//!
//! let secret_key = Scalar::random(&mut OsRng);
//! let public_key = EdwardsPoint::GENERATOR * &secret_key;
//! let compressed_public_key = public_key.compress();
//!
//! assert_eq!(compressed_public_key.to_bytes().len(), 57);
//!
//! let hashed_scalar = Scalar::hash::<ExpandMsgXof<Shake256>>(b"test", b"edwards448_XOF:SHAKE256_ELL2_RO_");
//! let input = hex_literal::hex!("c8c6c8f584e0c25efdb6af5ad234583c56dedd7c33e0c893468e96740fa0cf7f1a560667da40b7bde340a39252e89262fcf707d1180fd43400");
//! let expected_scalar = Scalar::from_canonical_bytes(&input.into()).unwrap();
//! assert_eq!(hashed_scalar, expected_scalar);
//!
//! let hashed_point = EdwardsPoint::hash::<ExpandMsgXof<Shake256>>(b"test", b"edwards448_XOF:SHAKE256_ELL2_RO_");
//! let expected = hex_literal::hex!("d15c4427b5c5611a53593c2be611fd3635b90272d331c7e6721ad3735e95dd8b9821f8e4e27501ce01aa3c913114052dce2e91e8ca050f4980");
//! let expected_point = CompressedEdwardsY(expected).decompress().unwrap();
//! assert_eq!(hashed_point, expected_point);
//!
//! let hashed_point = EdwardsPoint::hash_with_defaults(b"test");
//! assert_eq!(hashed_point, expected_point);
//! ```
//!
//! [`EdwardsPoint`] implements the [`elliptic_curve::Group`] and [`elliptic_curve::group::GroupEncoding`]
//! and [`Scalar`] implements [`elliptic_curve::Field`] and [`elliptic_curve::PrimeField`] traits.
#![deny(unused_attributes, unused_imports, unused_mut, unused_must_use)]
#![allow(non_snake_case)]
#![cfg_attr(all(not(feature = "alloc"), not(feature = "std")), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    clippy::mod_module_files
)]
#![deny(clippy::unwrap_used)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{boxed::Box, vec::Vec};

// Internal macros. Must come first!
#[macro_use]
pub(crate) mod macros;

pub use elliptic_curve;
pub use rand_core;
pub use sha3;
pub use subtle;

// As usual, we will use this file to carefully define the API/ what we expose to the user
pub(crate) mod constants;
pub(crate) mod curve;
pub(crate) mod decaf;
pub(crate) mod field;
pub(crate) mod ristretto;
#[cfg(feature = "signing")]
pub(crate) mod sign;

pub(crate) use field::{GOLDILOCKS_BASE_POINT, TWISTED_EDWARDS_BASE_POINT};

pub use curve::{
    AffinePoint, CompressedEdwardsY, EdwardsPoint, MontgomeryPoint, ProjectiveMontgomeryPoint,
};
pub use decaf::{AffinePoint as DecafAffinePoint, CompressedDecaf, DecafPoint};
pub use field::{Scalar, ScalarBytes, WideScalarBytes, MODULUS_LIMBS, ORDER, WIDE_ORDER};
pub use ristretto::{CompressedRistretto, RistrettoPoint};
#[cfg(feature = "signing")]
pub use sign::*;

use elliptic_curve::{
    bigint::{ArrayEncoding, ByteArray, U448},
    generic_array::typenum::U57,
    point::PointCompression,
    Curve, FieldBytesEncoding, PrimeCurve,
};

/// Edwards448 curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ed448;

/// Bytes of the Ed448 field
pub type Ed448FieldBytes = elliptic_curve::FieldBytes<Ed448>;

/// Scalar bits of the Ed448 scalar
pub type Ed448ScalarBits = elliptic_curve::scalar::ScalarBits<Ed448>;

/// Non-zero scalar of the Ed448 scalar
pub type Ed448NonZeroScalar = elliptic_curve::NonZeroScalar<Ed448>;

unsafe impl Send for Ed448 {}
unsafe impl Sync for Ed448 {}

impl Curve for Ed448 {
    type FieldBytesSize = U57;
    type Uint = U448;

    const ORDER: U448 = ORDER;
}

impl PrimeCurve for Ed448 {}

impl PointCompression for Ed448 {
    const COMPRESS_POINTS: bool = true;
}

impl FieldBytesEncoding<Ed448> for U448 {
    fn decode_field_bytes(field_bytes: &Ed448FieldBytes) -> Self {
        let data = ByteArray::<U448>::from_slice(field_bytes);
        U448::from_le_byte_array(*data)
    }

    fn encode_field_bytes(&self) -> Ed448FieldBytes {
        let mut data = Ed448FieldBytes::default();
        data.copy_from_slice(&self.to_le_byte_array()[..]);
        data
    }
}

#[cfg(feature = "zeroize")]
impl elliptic_curve::CurveArithmetic for Ed448 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = EdwardsPoint;
    type Scalar = Scalar;
}

/// Decaf448 curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Decaf448;

/// Bytes of the Decaf448 field
pub type Decaf448FieldBytes = elliptic_curve::FieldBytes<Decaf448>;

/// Scalar bits of the Decaf448 scalar
pub type Decaf448ScalarBits = elliptic_curve::scalar::ScalarBits<Decaf448>;

/// Non-zero scalar of the Decaf448 scalar
pub type Decaf448NonZeroScalar = elliptic_curve::NonZeroScalar<Decaf448>;

unsafe impl Send for Decaf448 {}
unsafe impl Sync for Decaf448 {}

impl Curve for Decaf448 {
    type FieldBytesSize = U57;
    type Uint = U448;

    const ORDER: U448 = ORDER;
}

impl PrimeCurve for Decaf448 {}

impl PointCompression for Decaf448 {
    const COMPRESS_POINTS: bool = true;
}

impl FieldBytesEncoding<Decaf448> for U448 {
    fn decode_field_bytes(field_bytes: &Decaf448FieldBytes) -> Self {
        let data = ByteArray::<U448>::from_slice(field_bytes);
        U448::from_le_byte_array(*data)
    }

    fn encode_field_bytes(&self) -> Decaf448FieldBytes {
        let mut data = Decaf448FieldBytes::default();
        data.copy_from_slice(&self.to_le_byte_array()[..]);
        data
    }
}

#[cfg(feature = "zeroize")]
impl elliptic_curve::CurveArithmetic for Decaf448 {
    type AffinePoint = DecafAffinePoint;
    type ProjectivePoint = DecafPoint;
    type Scalar = Scalar;
}
