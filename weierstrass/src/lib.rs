#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc = include_str!("../README.md")]

mod affine;
mod field;
mod projective;

pub use crate::{affine::AffinePoint, projective::ProjectivePoint};
pub use elliptic_curve::{self, Field, FieldBytes, PrimeCurve, PrimeField};

use elliptic_curve::{AffineArithmetic, ProjectiveArithmetic, ScalarArithmetic};

/// Weierstrass curve parameters.
pub trait WeierstrassCurve:
    PrimeCurve
    + ScalarArithmetic
    + AffineArithmetic<AffinePoint = AffinePoint<Self>>
    + ProjectiveArithmetic<ProjectivePoint = ProjectivePoint<Self>>
{
    /// Base field element type.
    type FieldElement: PrimeField<Repr = FieldBytes<Self>>;

    /// Zero element of the base field.
    // TODO(tarcieri): use `Field` trait instead. See zkcrypto/ff#87
    const ZERO: Self::FieldElement;

    /// Multiplicative identity of the base field.
    // TODO(tarcieri): use `Field` trait instead. See zkcrypto/ff#87
    const ONE: Self::FieldElement;

    /// Coefficient `a` in the curve equation.
    const EQUATION_A: Self::FieldElement;

    /// Coefficient `b` in the curve equation.
    const EQUATION_B: Self::FieldElement;

    /// Generator point's affine coordinates: (x, y).
    const GENERATOR: (Self::FieldElement, Self::FieldElement);
}
