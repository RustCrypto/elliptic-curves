#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
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
pub use montgomery::{
    MontgomeryPoint, MontgomeryScalar, MontgomeryScalarBytes, MontgomeryXpoint,
    ProjectiveMontgomeryPoint, ProjectiveMontgomeryXpoint, WideMontgomeryScalarBytes,
};
#[cfg(feature = "signing")]
pub use sign::*;

use elliptic_curve::{
    Curve, CurveArithmetic, FieldBytes, FieldBytesEncoding, NonZeroScalar, PrimeCurve,
    array::typenum::{U56, U57},
    bigint::{ArrayEncoding, Odd, U448},
    point::PointCompression,
};
use hash2curve::{ExpandMsgXof, GroupDigest};
use sha3::Shake256;

/// Edwards448 curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ed448;

/// Bytes of the Ed448 field
pub type Ed448FieldBytes = FieldBytes<Ed448>;

/// Scalar bits of the Ed448 scalar
#[cfg(feature = "bits")]
pub type Ed448ScalarBits = elliptic_curve::scalar::ScalarBits<Ed448>;

/// Non-zero scalar of the Ed448 scalar
pub type Ed448NonZeroScalar = NonZeroScalar<Ed448>;

impl Curve for Ed448 {
    type FieldBytesSize = U57;
    type Uint = U448;

    const ORDER: Odd<U448> = ORDER;
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

impl CurveArithmetic for Ed448 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = EdwardsPoint;
    type Scalar = EdwardsScalar;
}

impl GroupDigest for Ed448 {
    const HASH_TO_CURVE_ID: &[u8] = b"edwards448_XOF:SHAKE256_ELL2_RO_";
    const ENCODE_TO_CURVE_ID: &[u8] = b"edwards448_XOF:SHAKE256_ELL2_NU_";

    type ExpandMsg = ExpandMsgXof<Shake256>;
}

/// Decaf448 curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Decaf448;

/// Bytes of the Decaf448 field
pub type Decaf448FieldBytes = FieldBytes<Decaf448>;

/// Scalar bits of the Decaf448 scalar
#[cfg(feature = "bits")]
pub type Decaf448ScalarBits = elliptic_curve::scalar::ScalarBits<Decaf448>;

/// Non-zero scalar of the Decaf448 scalar
pub type Decaf448NonZeroScalar = NonZeroScalar<Decaf448>;

impl Curve for Decaf448 {
    type FieldBytesSize = U56;
    type Uint = U448;

    const ORDER: Odd<U448> = ORDER;
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

impl CurveArithmetic for Decaf448 {
    type AffinePoint = DecafAffinePoint;
    type ProjectivePoint = DecafPoint;
    type Scalar = DecafScalar;
}

impl GroupDigest for Decaf448 {
    const HASH_TO_CURVE_ID: &[u8] = b"decaf448_XOF:SHAKE256_D448MAP_RO_";
    const ENCODE_TO_CURVE_ID: &[u8] = b"decaf448_XOF:SHAKE256_D448MAP_NU_";

    type ExpandMsg = ExpandMsgXof<Shake256>;
}

/// Curve448 curve.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Curve448;

/// Bytes of the Curve448 field
pub type Curve448FieldBytes = FieldBytes<Curve448>;

/// Scalar bits of the Curve448 scalar
#[cfg(feature = "bits")]
pub type Curve448ScalarBits = elliptic_curve::scalar::ScalarBits<Curve448>;

/// Non-zero scalar of the Curve448 scalar
pub type Curve448NonZeroScalar = NonZeroScalar<Curve448>;

impl Curve for Curve448 {
    type FieldBytesSize = U56;
    type Uint = U448;

    const ORDER: Odd<U448> = ORDER;
}

impl PrimeCurve for Curve448 {}

impl PointCompression for Curve448 {
    const COMPRESS_POINTS: bool = true;
}

impl FieldBytesEncoding<Curve448> for U448 {
    fn decode_field_bytes(field_bytes: &Curve448FieldBytes) -> Self {
        U448::from_le_slice(field_bytes)
    }

    fn encode_field_bytes(&self) -> Curve448FieldBytes {
        let mut data = Curve448FieldBytes::default();
        data.copy_from_slice(&self.to_le_byte_array()[..]);
        data
    }
}

impl CurveArithmetic for Curve448 {
    type AffinePoint = MontgomeryPoint;
    type ProjectivePoint = ProjectiveMontgomeryPoint;
    type Scalar = MontgomeryScalar;
}
