//! Distinguished identifier support.

use crate::{AffinePoint, Hash, Sm2};
use elliptic_curve::{
    sec1::{self, ToEncodedPoint},
    Error, Result,
};
use primeorder::PrimeCurveParams;
use sm3::{Digest, Sm3};

/// Type which represents distinguishing identifiers.
pub(crate) type DistId = str;

/// Compute user information hash `Z` according to [draft-shen-sm2-ecdsa § 5.1.4.4].
///
/// ```text
/// ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
/// ```
///
/// [draft-shen-sm2-ecdsa § 5.1.4.4]: https://datatracker.ietf.org/doc/html/draft-shen-sm2-ecdsa-02#section-5.1.4.4
pub(crate) fn hash_z(distid: &DistId, public_key: &impl AsRef<AffinePoint>) -> Result<Hash> {
    let entla: u16 = distid
        .len()
        .checked_mul(8)
        .and_then(|l| l.try_into().ok())
        .ok_or(Error)?;

    let mut sm3 = Sm3::new();
    sm3.update(entla.to_be_bytes());
    sm3.update(distid);
    sm3.update(Sm2::EQUATION_A.to_bytes());
    sm3.update(Sm2::EQUATION_B.to_bytes());
    sm3.update(Sm2::GENERATOR.0.to_bytes());
    sm3.update(Sm2::GENERATOR.1.to_bytes());

    match public_key.as_ref().to_encoded_point(false).coordinates() {
        sec1::Coordinates::Uncompressed { x, y } => {
            sm3.update(x);
            sm3.update(y);
            Ok(sm3.finalize())
        }
        _ => Err(Error),
    }
}
