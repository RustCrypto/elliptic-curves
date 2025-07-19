#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(non_snake_case)]
#![forbid(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    clippy::mod_module_files,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    unused_attributes,
    unused_imports,
    unused_mut,
    unused_must_use
)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
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
pub(crate) mod edwards;
pub(crate) mod field;
pub(crate) mod montgomery;
#[cfg(feature = "signing")]
pub(crate) mod sign;

pub(crate) use field::{GOLDILOCKS_BASE_POINT, TWISTED_EDWARDS_BASE_POINT};

pub use decaf::{
    AffinePoint as DecafAffinePoint, CompressedDecaf, DecafPoint, DecafScalar, DecafScalarBytes,
    WideDecafScalarBytes,
};
pub use edwards::{
    AffinePoint, CompressedEdwardsY, EdwardsPoint, EdwardsScalar, EdwardsScalarBytes,
    WideEdwardsScalarBytes,
};
pub use field::{MODULUS_LIMBS, ORDER, Scalar, WIDE_ORDER};
pub use montgomery::{MontgomeryPoint, ProjectiveMontgomeryPoint};
#[cfg(feature = "signing")]
pub use sign::*;

use elliptic_curve::{
    Curve, FieldBytesEncoding, PrimeCurve,
    array::typenum::{U28, U56, U57},
    bigint::{ArrayEncoding, U448},
    point::PointCompression,
};
use hash2curve::GroupDigest;

/// Edwards448 curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ed448;

/// Bytes of the Ed448 field
pub type Ed448FieldBytes = elliptic_curve::FieldBytes<Ed448>;

/// Scalar bits of the Ed448 scalar
#[cfg(feature = "bits")]
pub type Ed448ScalarBits = elliptic_curve::scalar::ScalarBits<Ed448>;

/// Non-zero scalar of the Ed448 scalar
pub type Ed448NonZeroScalar = elliptic_curve::NonZeroScalar<Ed448>;

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
        U448::from_le_slice(field_bytes)
    }

    fn encode_field_bytes(&self) -> Ed448FieldBytes {
        let mut data = Ed448FieldBytes::default();
        data.copy_from_slice(&self.to_le_byte_array()[..]);
        data
    }
}

impl elliptic_curve::CurveArithmetic for Ed448 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = EdwardsPoint;
    type Scalar = EdwardsScalar;
}

impl GroupDigest for Ed448 {
    type K = U28;
}

/// Decaf448 curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Decaf448;

/// Bytes of the Decaf448 field
pub type Decaf448FieldBytes = elliptic_curve::FieldBytes<Decaf448>;

/// Scalar bits of the Decaf448 scalar
#[cfg(feature = "bits")]
pub type Decaf448ScalarBits = elliptic_curve::scalar::ScalarBits<Decaf448>;

/// Non-zero scalar of the Decaf448 scalar
pub type Decaf448NonZeroScalar = elliptic_curve::NonZeroScalar<Decaf448>;

impl Curve for Decaf448 {
    type FieldBytesSize = U56;
    type Uint = U448;

    const ORDER: U448 = ORDER;
}

impl PrimeCurve for Decaf448 {}

impl PointCompression for Decaf448 {
    const COMPRESS_POINTS: bool = true;
}

impl FieldBytesEncoding<Decaf448> for U448 {
    fn decode_field_bytes(field_bytes: &Decaf448FieldBytes) -> Self {
        U448::from_le_slice(field_bytes)
    }

    fn encode_field_bytes(&self) -> Decaf448FieldBytes {
        let mut data = Decaf448FieldBytes::default();
        data.copy_from_slice(&self.to_le_byte_array()[..]);
        data
    }
}

impl elliptic_curve::CurveArithmetic for Decaf448 {
    type AffinePoint = DecafAffinePoint;
    type ProjectivePoint = DecafPoint;
    type Scalar = DecafScalar;
}

impl GroupDigest for Decaf448 {
    type K = U28;
}
