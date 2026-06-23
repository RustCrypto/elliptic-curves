#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod mul_backend;
#[cfg(feature = "hash2curve")]
pub mod osswu;
pub mod point_arithmetic;

mod affine;
#[cfg(feature = "dev")]
mod dev;
mod projective;
mod tables;

pub use crate::{
    affine::AffinePoint,
    mul_backend::MulBackend,
    projective::ProjectivePoint,
    tables::{LookupTable, Radix16Decomposition, Radix16Digits},
};
pub use elliptic_curve::{
    self, Field, FieldBytes, PrimeCurve, PrimeField, Scalar,
    array::{self, ArraySize, sizes::U1},
    bigint::{ByteOrder, modular::Retrieve},
    hazmat::FieldArithmetic,
    ops::Double,
};
pub use primefield::{FieldExt, PrimeFieldExt};

use elliptic_curve::{Curve, CurveArithmetic, sec1};

#[cfg(feature = "basepoint-table")]
pub use crate::tables::BasepointTable;

/// Parameters for elliptic curves of prime order which can be described by the short Weierstrass
/// equation.
pub trait PrimeCurveParams:
    Curve<FieldBytesSize: sec1::ModulusSize>
    + CurveArithmetic<
        AffinePoint = AffinePoint<Self>,
        ProjectivePoint = ProjectivePoint<Self>,
        Scalar: PrimeFieldExt,
    > + FieldArithmetic<FieldElement: PrimeFieldExt>
    + PrimeCurve
{
    /// [Point arithmetic](point_arithmetic) implementation, might be optimized for this specific curve
    type PointArithmetic: point_arithmetic::PointArithmetic<Self>;

    /// Scalar arithmetic backend implementation.
    type Backend: MulBackend<Self>;

    /// Coefficient `a` in the curve equation.
    const EQUATION_A: Self::FieldElement;

    /// Coefficient `b` in the curve equation.
    const EQUATION_B: Self::FieldElement;

    /// Generator point's affine coordinates: (x, y).
    const GENERATOR: (Self::FieldElement, Self::FieldElement);
}

/// Trait for specifying a constant-time basepoint table for a given curve.
#[cfg(feature = "basepoint-table")]
pub trait PrimeCurveWithBasepointTable<const WINDOW_SIZE: usize>:
    PrimeCurve + CurveArithmetic
{
    /// Basepoint table for this curve.
    const BASEPOINT_TABLE: &'static BasepointTable<
        <Self as CurveArithmetic>::ProjectivePoint,
        WINDOW_SIZE,
    >;
}
