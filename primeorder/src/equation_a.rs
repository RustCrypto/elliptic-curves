//! Support for formulas specialized to the short Weierstrass equation's
//! 𝒂-coefficient.
//!
//! This module is largely a workaround for things which should be possible
//! to implement more elegantly with future Rust features like
//! `generic_const_exprs` and `impl const Trait`.
//!
//! In absence of such features, we define ZSTs that identify properties of
//! the 𝒂-coefficient which could potentially be written as const expressions
//! on `PrimeCurveParams::EQUATION_A` in the future (including ones which
//! could be used as trait bounds).

/// Sealed trait which identifies special properties of the curve's
/// 𝒂-coefficient.
pub trait CurveEquationAProperties {}

/// The 𝒂-coefficient of the short Weierstrass equation is 0.
pub struct CurveEquationAIsZero {}

/// The 𝒂-coefficient of the short Weierstrass equation is -3.
pub struct CurveEquationAIsMinusThree {}

/// The 𝒂-coefficient of the short Weierstrass equation does not have specific
/// properties which allow for an optimized implementation.
pub struct CurveEquationAIsGeneric {}

impl CurveEquationAProperties for CurveEquationAIsZero {}
impl CurveEquationAProperties for CurveEquationAIsMinusThree {}
impl CurveEquationAProperties for CurveEquationAIsGeneric {}
