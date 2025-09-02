//! Traits for handling hash to curve.

use super::{ExpandMsg, MapToCurve, hash_to_field};
use elliptic_curve::ProjectivePoint;
use elliptic_curve::group::cofactor::CofactorGroup;

/// Hash arbitrary byte sequences to a valid group element.
pub trait GroupDigest: MapToCurve {
    /// Suite ID for the [hash to curve routine](Self::hash_from_bytes).
    const HASH_TO_CURVE_ID: &[u8];
    /// Suite ID for the  [encode to curve routine](Self::encode_from_bytes).
    const ENCODE_TO_CURVE_ID: &[u8];

    /// The `expand_message` function to use.
    type ExpandMsg: ExpandMsg<Self::SecurityLevel>;

    /// Computes the hash to curve routine.
    ///
    /// From <https://www.rfc-editor.org/rfc/rfc9380.html>:
    ///
    /// > Uniform encoding from byte strings to points in G.
    /// > That is, the distribution of its output is statistically close
    /// > to uniform in G.
    /// > This function is suitable for most applications requiring a random
    /// > oracle returning points in G assuming a cryptographically secure
    /// > hash function is used.
    ///
    /// # Errors
    ///
    /// When the chosen [`ExpandMsg`] implementation returns an error. See [`ExpandMsgXmdError`]
    /// and [`ExpandMsgXofError`] for examples.
    ///
    /// [`ExpandMsgXmdError`]: crate::ExpandMsgXmdError
    /// [`ExpandMsgXofError`]: crate::ExpandMsgXofError
    fn hash_from_bytes(
        msg: &[u8],
        dst: &[u8],
    ) -> Result<ProjectivePoint<Self>, <Self::ExpandMsg as ExpandMsg<Self::SecurityLevel>>::Error>
    {
        hash_from_bytes::<Self, Self::ExpandMsg>(&[msg], &[dst])
    }

    /// Computes the encode to curve routine.
    ///
    /// From <https://www.rfc-editor.org/rfc/rfc9380.html>:
    ///
    /// > Nonuniform encoding from byte strings to
    /// > points in G. That is, the distribution of its output is not
    /// > uniformly random in G: the set of possible outputs of
    /// > encode_to_curve is only a fraction of the points in G, and some
    /// > points in this set are more likely to be output than others.
    ///
    /// # Errors
    ///
    /// When the chosen [`ExpandMsg`] implementation returns an error. See [`ExpandMsgXmdError`]
    /// and [`ExpandMsgXofError`] for examples.
    ///
    /// [`ExpandMsgXmdError`]: crate::ExpandMsgXmdError
    /// [`ExpandMsgXofError`]: crate::ExpandMsgXofError
    fn encode_from_bytes(
        msg: &[u8],
        dst: &[u8],
    ) -> Result<ProjectivePoint<Self>, <Self::ExpandMsg as ExpandMsg<Self::SecurityLevel>>::Error>
    {
        encode_from_bytes::<Self, Self::ExpandMsg>(&[msg], &[dst])
    }
}

/// Computes the hash to curve routine.
/// See [`GroupDigest::hash_from_bytes()`] for more details.
///
/// For the `expand_message` call, `len_in_bytes = <Self::FieldElement as FromOkm>::Length * 2`.
/// This value must be less than `u16::MAX` or otherwise a compiler error will occur.
///
/// # Errors
///
/// When the chosen [`ExpandMsg`] implementation returns an error. See [`ExpandMsgXmdError`]
/// and [`ExpandMsgXofError`] for examples.
///
/// [`ExpandMsgXmdError`]: crate::ExpandMsgXmdError
/// [`ExpandMsgXofError`]: crate::ExpandMsgXofError
pub fn hash_from_bytes<C, X>(msg: &[&[u8]], dst: &[&[u8]]) -> Result<ProjectivePoint<C>, X::Error>
where
    C: MapToCurve,
    X: ExpandMsg<C::SecurityLevel>,
{
    let [u0, u1] = hash_to_field::<2, X, _, C::FieldElement, C::FieldLength>(msg, dst)?;
    let q0 = C::map_to_curve(u0);
    let q1 = C::map_to_curve(u1);
    Ok((q0 + q1).clear_cofactor())
}

/// Computes the encode to curve routine.
/// See [`GroupDigest::encode_from_bytes()`] for more details.
///
/// For the `expand_message` call, `len_in_bytes = <Self::FieldElement as FromOkm>::Length`.
///
/// # Errors
///
/// When the chosen [`ExpandMsg`] implementation returns an error. See [`ExpandMsgXmdError`]
/// and [`ExpandMsgXofError`] for examples.
///
/// [`ExpandMsgXmdError`]: crate::ExpandMsgXmdError
/// [`ExpandMsgXofError`]: crate::ExpandMsgXofError
pub fn encode_from_bytes<C, X>(msg: &[&[u8]], dst: &[&[u8]]) -> Result<ProjectivePoint<C>, X::Error>
where
    C: MapToCurve,
    X: ExpandMsg<C::SecurityLevel>,
{
    let [u] = hash_to_field::<1, X, _, C::FieldElement, C::FieldLength>(msg, dst)?;
    let q0 = C::map_to_curve(u);
    Ok(q0.clear_cofactor())
}

/// Computes the hash to field routine according to
/// <https://www.rfc-editor.org/rfc/rfc9380.html#section-5-4>
/// and returns a scalar.
///   
/// For the `expand_message` call, `len_in_bytes = <Self::FieldElement as FromOkm>::Length`.
/// This value must be less than `u16::MAX` or otherwise a compiler error will occur.
///
/// # Errors
///
/// When the chosen [`ExpandMsg`] implementation returns an error. See [`ExpandMsgXmdError`]
/// and [`ExpandMsgXofError`] for examples.
///
/// [`ExpandMsgXmdError`]: crate::ExpandMsgXmdError
/// [`ExpandMsgXofError`]: crate::ExpandMsgXofError
pub fn hash_to_scalar<C, X>(msg: &[&[u8]], dst: &[&[u8]]) -> Result<C::Scalar, X::Error>
where
    C: MapToCurve,
    X: ExpandMsg<C::SecurityLevel>,
{
    let [u] = hash_to_field::<1, X, _, C::Scalar, C::ScalarLength>(msg, dst)?;
    Ok(u)
}
