use digest::FixedOutput;
use digest::Update;
use elliptic_curve::PrimeCurve;
use elliptic_curve::array::typenum::IsLess;
use elliptic_curve::consts::{True, U65536};

use crate::ExpandMsg;
use crate::GroupDigest;

/// Elliptic curve parameters used by OPRF.
pub trait OprfParameters: GroupDigest + PrimeCurve {
    /// The `ID` parameter which identifies a particular elliptic curve
    /// as defined in [section 4 of RFC9497][oprf].
    ///
    /// [oprf]: https://www.rfc-editor.org/rfc/rfc9497.html#name-ciphersuites
    const ID: &'static [u8];

    /// The `Hash` parameter which assigns a particular hash function to this
    /// ciphersuite as defined in [section 4 of RFC9497][oprf].
    ///
    /// [oprf]: https://www.rfc-editor.org/rfc/rfc9497.html#name-ciphersuites
    type Hash: Default + FixedOutput<OutputSize: IsLess<U65536, Output = True>> + Update;

    /// The `expand_message` parameter which assigns a particular algorithm for `HashToGroup`
    /// and `HashToScalar` as defined in [section 4 of RFC9497][oprf].
    ///
    /// [oprf]: https://www.rfc-editor.org/rfc/rfc9497.html#name-ciphersuites
    type ExpandMsg: ExpandMsg<<Self as GroupDigest>::SecurityLevel>;
}
