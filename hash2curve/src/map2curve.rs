//! Traits for mapping field elements to points on the curve.

use elliptic_curve::ProjectivePoint;

use crate::HashToCurve;

/// Trait for converting field elements into a point via a mapping method like
/// Simplified Shallue-van de Woestijne-Ulas or Elligator.
pub trait MapToCurve<C: HashToCurve> {
    /// Map a field element into a curve point.
    fn map_to_curve(element: C::FieldElement) -> ProjectivePoint<C>;
}
