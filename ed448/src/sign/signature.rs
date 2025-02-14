use crate::{
    CompressedEdwardsY, EdwardsPoint, Scalar, ScalarBytes, SigningError, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use elliptic_curve::Group;

/// Ed448 signature as defined in [RFC8032 § 5.2.5]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    pub(crate) r: CompressedEdwardsY,
    pub(crate) s: [u8; 57],
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            r: CompressedEdwardsY::default(),
            s: [0u8; 57],
        }
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<Vec<u8>> for Signature {
    type Error = SigningError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<&Vec<u8>> for Signature {
    type Error = SigningError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = SigningError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != SIGNATURE_LENGTH {
            return Err(SigningError::InvalidSignatureLength);
        }

        let mut bytes = [0u8; SIGNATURE_LENGTH];
        bytes.copy_from_slice(value);
        Self::from_bytes(&bytes)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl TryFrom<Box<[u8]>> for Signature {
    type Error = SigningError;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

#[cfg(feature = "serde")]
impl serdect::serde::Serialize for Signature {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::array::serialize_hex_lower_or_bin(&self.to_bytes(), s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serdect::serde::Deserialize<'de> for Signature {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        let mut bytes = [0u8; SIGNATURE_LENGTH];
        serdect::array::deserialize_hex_or_bin(&mut bytes, d)?;
        Signature::from_bytes(&bytes).map_err(serdect::serde::de::Error::custom)
    }
}

impl Signature {
    /// Converts [`Signature`] to a byte array.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut bytes = [0u8; SIGNATURE_LENGTH];
        bytes[..57].copy_from_slice(self.r.as_bytes());
        bytes[57..].copy_from_slice(&self.s);
        bytes
    }

    /// Converts a byte array to a [`Signature`].
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LENGTH]) -> Result<Self, SigningError> {
        let mut r = [0u8; SECRET_KEY_LENGTH];
        r.copy_from_slice(&bytes[..SECRET_KEY_LENGTH]);
        let mut s = [0u8; SECRET_KEY_LENGTH];
        s.copy_from_slice(&bytes[SECRET_KEY_LENGTH..]);

        let r = CompressedEdwardsY(r);

        let big_r = r.decompress();
        if big_r.is_none().into() {
            return Err(SigningError::InvalidSignatureRComponent);
        }

        let big_r = big_r.expect("big_r is not none");
        if big_r.is_identity().into() {
            return Err(SigningError::InvalidSignatureRComponent);
        }

        if s[56] != 0x00 {
            return Err(SigningError::InvalidSignatureSComponent);
        }
        let s_bytes = ScalarBytes::from_slice(&s);
        let ss = Scalar::from_canonical_bytes(s_bytes);

        if ss.is_none().into() {
            return Err(SigningError::InvalidSignatureSComponent);
        }
        let sc = ss.expect("ss is not none");
        if sc.is_zero().into() {
            return Err(SigningError::InvalidSignatureSComponent);
        }

        Ok(Self { r, s })
    }

    /// The `r` value of the signature.
    pub fn r(&self) -> CompressedEdwardsY {
        self.r
    }

    /// The `s` value of the signature.
    pub fn s(&self) -> &[u8; SECRET_KEY_LENGTH] {
        &self.s
    }
}

impl From<InnerSignature> for Signature {
    fn from(inner: InnerSignature) -> Self {
        let mut s = [0u8; SECRET_KEY_LENGTH];
        s.copy_from_slice(&inner.s.to_bytes_rfc_8032());
        Self {
            r: inner.r.compress(),
            s,
        }
    }
}

impl TryFrom<Signature> for InnerSignature {
    type Error = SigningError;

    fn try_from(signature: Signature) -> Result<Self, Self::Error> {
        let s_bytes = ScalarBytes::from_slice(&signature.s);
        let s = Option::from(Scalar::from_canonical_bytes(s_bytes))
            .ok_or(SigningError::InvalidSignatureSComponent)?;
        let r = Option::from(signature.r.decompress())
            .ok_or(SigningError::InvalidSignatureRComponent)?;
        Ok(Self { r, s })
    }
}

pub(crate) struct InnerSignature {
    pub(crate) r: EdwardsPoint,
    pub(crate) s: Scalar,
}

#[cfg(feature = "serde")]
#[test]
fn serialization() {
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
    let signing_key = super::SigningKey::generate(&mut rng);
    let signature = signing_key.sign_raw(b"Hello, World!");

    let bytes = serde_bare::to_vec(&signature).unwrap();
    let signature2: Signature = serde_bare::from_slice(&bytes).unwrap();
    assert_eq!(signature, signature2);

    let string = serde_json::to_string(&signature).unwrap();
    let signature3: Signature = serde_json::from_str(&string).unwrap();
    assert_eq!(signature, signature3);
}
