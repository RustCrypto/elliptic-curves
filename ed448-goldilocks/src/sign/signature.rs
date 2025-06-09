use crate::*;
use elliptic_curve::array::Array;

pub use ed448::Signature;

impl From<InnerSignature> for Signature {
    fn from(inner: InnerSignature) -> Self {
        let mut s = [0u8; SECRET_KEY_LENGTH];
        s.copy_from_slice(&inner.s.to_bytes_rfc_8032());
        Self::from_components(inner.r.compress(), s)
    }
}

impl TryFrom<&Signature> for InnerSignature {
    type Error = SigningError;

    fn try_from(signature: &Signature) -> Result<Self, Self::Error> {
        let s_bytes: &Array<u8, _> = (signature.s_bytes()).into();
        let s = Option::from(Scalar::from_canonical_bytes(s_bytes))
            .ok_or(SigningError::InvalidSignatureSComponent)?;
        let r = Option::from(CompressedEdwardsY::from(*signature.r_bytes()).decompress())
            .ok_or(SigningError::InvalidSignatureRComponent)?;
        Ok(Self { r, s })
    }
}

pub(crate) struct InnerSignature {
    pub(crate) r: EdwardsPoint,
    pub(crate) s: Scalar,
}

impl TryFrom<Signature> for InnerSignature {
    type Error = SigningError;

    fn try_from(signature: Signature) -> Result<Self, Self::Error> {
        Self::try_from(&signature)
    }
}
