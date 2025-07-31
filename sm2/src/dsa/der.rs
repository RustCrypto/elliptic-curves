//! ASN.1 DER encoding for SM2 signatures.
//!
//! This module provides a type for representing SM2 signatures in ASN.1 DER format.
//! It is used to encode and decode SM2 signatures to and from DER-encoded bytes.

use core::{
    fmt::{self, Debug},
    ops::{Add, Range},
};

use crate::FieldBytesSize;

use der::{
    self, Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence,
    Tag, Writer, asn1::UintRef,
};

use elliptic_curve::{
    array::{Array, typenum::Unsigned},
    consts::U9,
};

#[cfg(feature = "alloc")]
use {
    crate::pkcs8::spki::{SignatureBitStringEncoding, der::asn1::BitString},
    alloc::{boxed::Box, vec::Vec},
    signature::SignatureEncoding,
};

#[cfg(feature = "serde")]
use serdect::serde::{Deserialize, Serialize, de, ser};

type MaxOverhead = U9;

/// Maximum size of an ASN.1 DER encoded signature for the given elliptic curve.
type MaxSize = <<FieldBytesSize as Add>::Output as Add<MaxOverhead>>::Output;

/// Byte array containing a serialized ASN.1 signature
type SignatureBytes = Array<u8, MaxSize>;

/// ASN.1 DER-encoded SM2 signature.
pub struct Signature {
    /// ASN.1 DER-encoded signature data
    bytes: SignatureBytes,

    /// Range of the `r` value within the signature
    r_range: Range<usize>,

    /// Range of the `s` value within the signature
    s_range: Range<usize>,
}

#[allow(clippy::len_without_is_empty)]
impl Signature {
    /// Parse signature from DER-encoded bytes.
    pub fn from_bytes(input: &[u8]) -> signature::Result<Self> {
        let SignatureRef { r, s } =
            SignatureRef::from_der(input).map_err(|_| signature::Error::new())?;

        if r.as_bytes().len() > FieldBytesSize::USIZE || s.as_bytes().len() > FieldBytesSize::USIZE
        {
            return Err(signature::Error::new());
        }

        let r_range = find_scalar_range(input, r.as_bytes())?;
        let s_range = find_scalar_range(input, s.as_bytes())?;

        if s_range.end != input.len() {
            return Err(signature::Error::new());
        }

        let mut bytes = SignatureBytes::default();
        bytes[..s_range.end].copy_from_slice(input);

        Ok(Signature {
            bytes,
            r_range,
            s_range,
        })
    }

    /// Create an ASN.1 DER encoded signature from big endian `r` and `s` scalar
    /// components.
    pub(crate) fn from_components(r: &[u8], s: &[u8]) -> der::Result<Self> {
        let sig = SignatureRef {
            r: UintRef::new(r)?,
            s: UintRef::new(s)?,
        };
        let mut bytes = SignatureBytes::default();

        sig.encode_to_slice(&mut bytes)?
            .try_into()
            .map_err(|_| Tag::Sequence.value_error().into())
    }

    /// Borrow this signature as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.len()]
    }

    /// Serialize this signature as a boxed byte slice
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.as_bytes().to_vec().into_boxed_slice()
    }

    /// Serialize this signature as a vector
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Get the length of the signature in bytes
    pub fn len(&self) -> usize {
        self.s_range.end
    }

    /// Get the `r` component of the signature (leading zeros removed)
    pub(crate) fn r(&self) -> &[u8] {
        &self.bytes[self.r_range.clone()]
    }

    /// Get the `s` component of the signature (leading zeros removed)
    pub(crate) fn s(&self) -> &[u8] {
        &self.bytes[self.s_range.clone()]
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Clone for Signature {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            r_range: self.r_range.clone(),
            s_range: self.s_range.clone(),
        }
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sm2::der::Signature(")?;

        for &byte in self.as_ref() {
            write!(f, "{byte:02X}")?;
        }

        write!(f, ")")
    }
}

impl<'a> Decode<'a> for Signature {
    type Error = der::Error;

    fn decode<R: Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let header = Header::peek(reader)?;
        header.tag.assert_eq(Tag::Sequence)?;

        let mut buf = SignatureBytes::default();
        let len = (header.encoded_len()? + header.length)?;
        let slice = buf
            .get_mut(..usize::try_from(len)?)
            .ok_or_else(|| reader.error(Tag::Sequence.length_error()))?;

        reader.read_into(slice)?;
        Self::from_bytes(slice).map_err(|_| reader.error(Tag::Integer.value_error()))
    }
}

impl Encode for Signature {
    fn encoded_len(&self) -> der::Result<Length> {
        Length::try_from(self.len())
    }

    fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write(self.as_bytes())
    }
}

impl FixedTag for Signature {
    const TAG: Tag = Tag::Sequence;
}

impl From<crate::dsa::Signature> for Signature {
    fn from(sig: crate::dsa::Signature) -> Signature {
        sig.to_der()
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(input: &[u8]) -> signature::Result<Self> {
        Self::from_bytes(input)
    }
}

impl TryFrom<Signature> for crate::dsa::Signature {
    type Error = signature::Error;

    fn try_from(sig: Signature) -> signature::Result<crate::dsa::Signature> {
        let mut bytes = crate::dsa::SignatureBytes::default();
        let r_begin = FieldBytesSize::USIZE.saturating_sub(sig.r().len());
        let s_begin = bytes.len().saturating_sub(sig.s().len());
        bytes[r_begin..FieldBytesSize::USIZE].copy_from_slice(sig.r());
        bytes[s_begin..].copy_from_slice(sig.s());
        Self::try_from(bytes.as_slice())
    }
}

#[cfg(feature = "alloc")]
impl From<Signature> for Box<[u8]> {
    fn from(signature: Signature) -> Box<[u8]> {
        signature.to_bytes()
    }
}

#[cfg(feature = "alloc")]
impl SignatureEncoding for Signature {
    type Repr = Box<[u8]>;

    fn to_bytes(&self) -> Self::Repr {
        self.to_bytes()
    }

    fn encoded_len(&self) -> usize {
        self.len()
    }
}

#[cfg(feature = "alloc")]
impl SignatureBitStringEncoding for Signature {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::new(0, self.to_vec())
    }
}

#[cfg(feature = "serde")]
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serdect::slice::serialize_hex_upper_or_bin(&self.as_bytes(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut buf = SignatureBytes::default();
        let slice = serdect::slice::deserialize_hex_or_bin(&mut buf, deserializer)?;
        Self::try_from(slice).map_err(de::Error::custom)
    }
}

struct SignatureRef<'a> {
    pub r: UintRef<'a>,
    pub s: UintRef<'a>,
}

impl EncodeValue for SignatureRef<'_> {
    fn value_len(&self) -> der::Result<Length> {
        self.r.encoded_len()? + self.s.encoded_len()?
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.r.encode(encoder)?;
        self.s.encode(encoder)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for SignatureRef<'a> {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        Ok(Self {
            r: UintRef::decode(reader)?,
            s: UintRef::decode(reader)?,
        })
    }
}

impl<'a> Sequence<'a> for SignatureRef<'a> {}

/// Locate the range within a slice at which a particular subslice is located
fn find_scalar_range(outer: &[u8], inner: &[u8]) -> signature::Result<Range<usize>> {
    let outer_start = outer.as_ptr() as usize;
    let inner_start = inner.as_ptr() as usize;
    let start = inner_start
        .checked_sub(outer_start)
        .ok_or_else(signature::Error::new)?;
    let end = start
        .checked_add(inner.len())
        .ok_or_else(signature::Error::new)?;
    Ok(Range { start, end })
}
