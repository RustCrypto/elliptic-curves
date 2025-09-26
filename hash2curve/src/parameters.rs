use elliptic_curve::CurveArithmetic;
use elliptic_curve::array::typenum::{NonZero, Unsigned};
use elliptic_curve::array::{Array, ArraySize};
use elliptic_curve::group::cofactor::CofactorGroup;
use elliptic_curve::ops::Reduce;

/// Trait defining curve parameters for hash-to-curve operations.
pub trait HashToCurve:
    CurveArithmetic<ProjectivePoint: CofactorGroup<Subgroup = Self::ProjectivePoint>>
{
    /// The target security level in bytes:
    /// <https://www.rfc-editor.org/rfc/rfc9380.html#section-8.9-2.2>
    /// <https://www.rfc-editor.org/rfc/rfc9380.html#name-target-security-levels>
    type SecurityLevel: Unsigned;
    /// The field element representation for a group value with multiple elements.
    type FieldElement: Reduce<Array<u8, Self::Length>> + Default + Copy;
    /// The `L` parameter as specified in the [RFC](https://www.rfc-editor.org/rfc/rfc9380.html#section-5-6).
    type Length: ArraySize + NonZero;
}
