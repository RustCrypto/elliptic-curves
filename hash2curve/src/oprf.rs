use digest::FixedOutput;
use digest::Update;
use elliptic_curve::PrimeCurve;
use elliptic_curve::array::typenum::IsLess;
use elliptic_curve::consts::{True, U65536};

use crate::{ExpandMsg, GroupDigest};

/// Elliptic curve parameters used by OPRF.
pub trait OprfParameters:
    GroupDigest<
        ExpandMsg: ExpandMsg<
            Self::SecurityLevel,
            Hash: Default + FixedOutput<OutputSize: IsLess<U65536, Output = True>> + Update,
        >,
    > + PrimeCurve
{
    /// The `ID` parameter which identifies a particular elliptic curve
    /// as defined in [section 4 of RFC9497][oprf].
    ///
    /// [oprf]: https://www.rfc-editor.org/rfc/rfc9497.html#name-ciphersuites
    const ID: &'static [u8];
}
