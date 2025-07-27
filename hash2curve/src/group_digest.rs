//! Traits for handling hash to curve.

use super::{ExpandMsg, MapToCurve, hash_to_field};
use elliptic_curve::array::typenum::Unsigned;
use elliptic_curve::{ProjectivePoint, Result};

/// Hash arbitrary byte sequences to a valid group element.
pub trait GroupDigest: MapToCurve {
    /// The target security level in bytes:
    /// <https://www.rfc-editor.org/rfc/rfc9380.html#section-8.9-2.2>
    /// <https://www.rfc-editor.org/rfc/rfc9380.html#name-target-security-levels>
    type K: Unsigned;

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
    /// - `len_in_bytes > u16::MAX`
    /// - See implementors of [`ExpandMsg`] for additional errors:
    ///   - [`ExpandMsgXmd`]
    ///   - [`ExpandMsgXof`]
    ///
    /// `len_in_bytes = <Self::FieldElement as FromOkm>::Length * 2`
    ///
    /// [`ExpandMsgXmd`]: crate::ExpandMsgXmd
    /// [`ExpandMsgXof`]: crate::ExpandMsgXof
    fn hash_from_bytes<X>(msg: &[&[u8]], dst: &[&[u8]]) -> Result<ProjectivePoint<Self>>
    where
        X: ExpandMsg<Self::K>,
    {
        let [u0, u1] = hash_to_field::<2, X, _, Self::FieldElement>(msg, dst)?;
        let q0 = Self::map_to_curve(u0);
        let q1 = Self::map_to_curve(u1);
        Ok(Self::add_and_map_to_subgroup(q0, q1))
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
    /// - `len_in_bytes > u16::MAX`
    /// - See implementors of [`ExpandMsg`] for additional errors:
    ///   - [`ExpandMsgXmd`]
    ///   - [`ExpandMsgXof`]
    ///
    /// `len_in_bytes = <Self::FieldElement as FromOkm>::Length`
    ///
    /// [`ExpandMsgXmd`]: crate::ExpandMsgXmd
    /// [`ExpandMsgXof`]: crate::ExpandMsgXof
    fn encode_from_bytes<X>(msg: &[&[u8]], dst: &[&[u8]]) -> Result<ProjectivePoint<Self>>
    where
        X: ExpandMsg<Self::K>,
    {
        let [u] = hash_to_field::<1, X, _, Self::FieldElement>(msg, dst)?;
        let q0 = Self::map_to_curve(u);
        Ok(Self::map_to_subgroup(q0))
    }

    /// Computes the hash to field routine according to
    /// <https://www.rfc-editor.org/rfc/rfc9380.html#section-5-4>
    /// and returns a scalar.
    ///
    /// # Errors
    /// - `len_in_bytes > u16::MAX`
    /// - See implementors of [`ExpandMsg`] for additional errors:
    ///   - [`ExpandMsgXmd`]
    ///   - [`ExpandMsgXof`]
    ///
    /// `len_in_bytes = <Self::Scalar as FromOkm>::Length`
    ///
    /// [`ExpandMsgXmd`]: crate::ExpandMsgXmd
    /// [`ExpandMsgXof`]: crate::ExpandMsgXof
    fn hash_to_scalar<X>(msg: &[&[u8]], dst: &[&[u8]]) -> Result<Self::Scalar>
    where
        X: ExpandMsg<Self::K>,
    {
        let [u] = hash_to_field::<1, X, _, Self::Scalar>(msg, dst)?;
        Ok(u)
    }
}
