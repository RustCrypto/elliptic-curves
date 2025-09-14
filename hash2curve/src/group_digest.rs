//! Traits for handling hash to curve.

use crate::{ExpandMsg, MapToCurve};
use elliptic_curve::ProjectivePoint;

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
        crate::hash_from_bytes::<Self, Self::ExpandMsg>(&[msg], &[dst])
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
        crate::encode_from_bytes::<Self, Self::ExpandMsg>(&[msg], &[dst])
    }
}
