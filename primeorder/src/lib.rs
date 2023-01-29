#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc = include_str!("../README.md")]

pub mod equation_a;

mod affine;
mod field;
mod projective;

pub use crate::{affine::AffinePoint, projective::ProjectivePoint};
pub use elliptic_curve::{self, point::Double, Field, FieldBytes, PrimeCurve, PrimeField};

use elliptic_curve::CurveArithmetic;

/// Parameters for elliptic curves of prime order which can be described by the
/// short Weierstrass equation.
pub trait PrimeCurveParams:
    PrimeCurve
    + CurveArithmetic
    + CurveArithmetic<AffinePoint = AffinePoint<Self>>
    + CurveArithmetic<ProjectivePoint = ProjectivePoint<Self>>
{
    /// Base field element type.
    type FieldElement: PrimeField<Repr = FieldBytes<Self>>;

    /// Special properties of the `a`-coefficient.
    type EquationAProperties: equation_a::EquationAProperties;

    /// Coefficient `a` in the curve equation.
    const EQUATION_A: Self::FieldElement;

    /// Coefficient `b` in the curve equation.
    const EQUATION_B: Self::FieldElement;

    /// Generator point's affine coordinates: (x, y).
    const GENERATOR: (Self::FieldElement, Self::FieldElement);
}
