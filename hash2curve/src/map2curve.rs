//! Traits for mapping field elements to points on the curve.

use elliptic_curve::{CurveArithmetic, ProjectivePoint};

use super::FromOkm;

/// Trait for converting field elements into a point via a mapping method like
/// Simplified Shallue-van de Woestijne-Ulas or Elligator.
pub trait MapToCurve: CurveArithmetic<Scalar: FromOkm> {
    /// The intermediate representation, an element of the curve which may or may not
    /// be in the curve subgroup.
    type CurvePoint;
    /// The field element representation for a group value with multiple elements.
    type FieldElement: FromOkm + Default + Copy;

    /// Map a field element into a curve point.
    fn map_to_curve(element: Self::FieldElement) -> Self::CurvePoint;

    /// Map a curve point to a point in the curve subgroup.
    /// This is usually done by clearing the cofactor, if necessary.
    fn map_to_subgroup(point: Self::CurvePoint) -> ProjectivePoint<Self>;

    /// Combine two curve points into a point in the curve subgroup.
    /// This is usually done by clearing the cofactor of the sum. In case
    /// addition is not implemented for `Self::CurvePoint`, then both terms
    /// must be mapped to the subgroup individually before being added.
    fn add_and_map_to_subgroup(
        lhs: Self::CurvePoint,
        rhs: Self::CurvePoint,
    ) -> ProjectivePoint<Self> {
        Self::map_to_subgroup(lhs) + Self::map_to_subgroup(rhs)
    }
}
