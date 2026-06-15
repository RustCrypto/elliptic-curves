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

#[cfg(feature = "hash2curve")]
pub mod osswu;
pub mod point_arithmetic;

mod affine;
#[cfg(feature = "basepoint-table")]
mod basepoint_table;
#[cfg(feature = "dev")]
mod dev;
mod lookup_table;
mod projective;
mod radix16;

pub use crate::{
    affine::AffinePoint,
    lookup_table::LookupTable,
    projective::ProjectivePoint,
    radix16::{Radix16Decomposition, Radix16Digits},
};
pub use elliptic_curve::{
    self, Field, FieldBytes, PrimeCurve, PrimeField, Scalar,
    array::{self, ArraySize, sizes::U1},
    bigint::modular::Retrieve,
    point::Double,
};

use elliptic_curve::{
    Curve, CurveArithmetic, Generate,
    ops::{Add, Invert, LinearCombination, MulVartime},
    sec1,
    subtle::CtOption,
};

#[cfg(feature = "basepoint-table")]
pub use crate::basepoint_table::BasepointTable;

/// Parameters for elliptic curves of prime order which can be described by the
/// short Weierstrass equation.
pub trait PrimeCurveParams:
    Curve<FieldBytesSize: ModulusSize>
    + PrimeCurve
    + CurveArithmetic<AffinePoint = AffinePoint<Self>, ProjectivePoint = ProjectivePoint<Self>>
{
    /// Base field element type.
    type FieldElement: Generate
        + Invert<Output = CtOption<Self::FieldElement>>
        + PrimeField<Repr = FieldBytes<Self>>
        + Retrieve<Output = Self::Uint>;

    /// [Point arithmetic](point_arithmetic) implementation, might be optimized for this specific curve
    type PointArithmetic: point_arithmetic::PointArithmetic<Self>;

    /// Coefficient `a` in the curve equation.
    const EQUATION_A: Self::FieldElement;

    /// Coefficient `b` in the curve equation.
    const EQUATION_B: Self::FieldElement;

    /// Generator point's affine coordinates: (x, y).
    const GENERATOR: (Self::FieldElement, Self::FieldElement);

    /// Are field element serializations for this curve big endian?
    // TODO(tarcieri): make this a property of the scalar type, e.g. zkcrypto/ff#158
    const FIELD_REPR_IS_BE: bool = true;

    /// Multiplication by the generator.
    ///
    /// This is overridable to make it possible to plug in a basepoint table.
    fn mul_by_generator(k: &Scalar<Self>) -> ProjectivePoint<Self> {
        ProjectivePoint::GENERATOR * k
    }

    /// Variable-time multiplication by the generator.
    ///
    /// This is overridable to make it possible to plug in a basepoint table.
    fn mul_by_generator_vartime(k: &Scalar<Self>) -> ProjectivePoint<Self> {
        ProjectivePoint::GENERATOR.mul_vartime(k)
    }

    /// Multiply `a` by the generator of the prime-order subgroup, adding the result to the point
    /// `P` multiplied by the scalar `b`, i.e. compute `aG + bP`.
    fn mul_by_generator_and_mul_add_vartime(
        a: &Scalar<Self>,
        b_scalar: &Scalar<Self>,
        b_point: &ProjectivePoint<Self>,
    ) -> ProjectivePoint<Self> {
        ProjectivePoint::<Self>::lincomb_vartime(&[
            (ProjectivePoint::GENERATOR, *a),
            (*b_point, *b_scalar),
        ])
    }
}

/// Acceptable modulus sizes can be used as [`Radix16Digits`] and a [`sec1::ModulusSize`].
pub trait ModulusSize:
    ArraySize<ArrayType<u8>: Copy>
    + Add<Output: Add<U1, Output: ArraySize>> // Radix16Digits
    + sec1::ModulusSize<CompressedPointSize: ArraySize<ArrayType<u8>: Copy>>
{
}

impl<T> ModulusSize for T
where
    T: ArraySize<ArrayType<u8>: Copy>,
    T: Add<Output: Add<U1, Output: ArraySize>>, // Radix16Digits
    T: sec1::ModulusSize<CompressedPointSize: ArraySize<ArrayType<u8>: Copy>>,
{
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
