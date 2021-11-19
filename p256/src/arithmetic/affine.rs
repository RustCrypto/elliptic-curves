//! Affine points

use super::{FieldElement, ProjectivePoint, CURVE_EQUATION_A, CURVE_EQUATION_B, MODULUS};
use crate::{CompressedPoint, EncodedPoint, FieldBytes, NistP256, Scalar};
use core::ops::{Mul, Neg};
use elliptic_curve::{
    bigint::Encoding,
    generic_array::arr,
    group::{prime::PrimeCurveAffine, GroupEncoding},
    sec1::Tag,
    sec1::{self, FromEncodedPoint, ToCompactEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    AffineArithmetic, AffineXCoordinate, Curve, DecompactPoint, DecompressPoint, Error, Result,
};

#[cfg(feature = "serde")]
use elliptic_curve::serde::{de, ser, Deserialize, Serialize};

impl AffineArithmetic for NistP256 {
    type AffinePoint = AffinePoint;
}

/// A point on the secp256r1 curve in affine coordinates.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct AffinePoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(super) infinity: Choice,
}

impl PrimeCurveAffine for AffinePoint {
    type Scalar = Scalar;
    type Curve = ProjectivePoint;

    /// Returns the identity of the group: the point at infinity.
    fn identity() -> AffinePoint {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
            infinity: Choice::from(1),
        }
    }

    /// Returns the base point of P-256.
    fn generator() -> AffinePoint {
        // NIST P-256 basepoint in affine coordinates:
        // x = 6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296
        // y = 4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5
        AffinePoint {
            x: FieldElement::from_bytes(&arr![u8;
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                0xd8, 0x98, 0xc2, 0x96
            ])
            .unwrap(),
            y: FieldElement::from_bytes(&arr![u8;
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                0x37, 0xbf, 0x51, 0xf5
            ])
            .unwrap(),
            infinity: Choice::from(0),
        }
    }

    /// Is this point the identity point?
    fn is_identity(&self) -> Choice {
        self.infinity
    }

    /// Convert to curve representation.
    fn to_curve(&self) -> ProjectivePoint {
        ProjectivePoint::from(*self)
    }
}

impl AffineXCoordinate<NistP256> for AffinePoint {
    fn x(&self) -> FieldBytes {
        self.x.to_bytes()
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &AffinePoint, b: &AffinePoint, choice: Choice) -> AffinePoint {
        AffinePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            infinity: Choice::conditional_select(&a.infinity, &b.infinity, choice),
        }
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &AffinePoint) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y) & self.infinity.ct_eq(&other.infinity)
    }
}

impl Default for AffinePoint {
    fn default() -> Self {
        Self::identity()
    }
}

impl DefaultIsZeroes for AffinePoint {}

impl Eq for AffinePoint {}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &AffinePoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl DecompressPoint<NistP256> for AffinePoint {
    fn decompress(x_bytes: &FieldBytes, y_is_odd: Choice) -> CtOption<Self> {
        FieldElement::from_bytes(x_bytes).and_then(|x| {
            let alpha = x * &x * &x + &(CURVE_EQUATION_A * &x) + &CURVE_EQUATION_B;
            let beta = alpha.sqrt();

            beta.map(|beta| {
                let y = FieldElement::conditional_select(
                    &(MODULUS - &beta),
                    &beta,
                    beta.is_odd().ct_eq(&y_is_odd),
                );

                Self {
                    x,
                    y,
                    infinity: Choice::from(0),
                }
            })
        })
    }
}

impl GroupEncoding for AffinePoint {
    type Repr = CompressedPoint;

    /// NOTE: not constant-time with respect to identity point
    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        EncodedPoint::from_bytes(bytes)
            .map(|point| CtOption::new(point, Choice::from(1)))
            .unwrap_or_else(|_| {
                // SEC1 identity encoding is technically 1-byte 0x00, but the
                // `GroupEncoding` API requires a fixed-width `Repr`
                let is_identity = bytes.ct_eq(&Self::Repr::default());
                CtOption::new(EncodedPoint::identity(), is_identity)
            })
            .and_then(|point| Self::from_encoded_point(&point))
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        let encoded = self.to_encoded_point(true);
        let mut result = CompressedPoint::default();
        result[..encoded.len()].copy_from_slice(encoded.as_bytes());
        result
    }
}

impl DecompactPoint<NistP256> for AffinePoint {
    fn decompact(x_bytes: &FieldBytes) -> CtOption<Self> {
        FieldElement::from_bytes(x_bytes).and_then(|x| {
            let montgomery_y = (x * &x * &x + &(CURVE_EQUATION_A * &x) + &CURVE_EQUATION_B).sqrt();
            montgomery_y.map(|montgomery_y| {
                // Convert to canonical form for comparisons
                let y = montgomery_y.as_canonical();
                let p_y = MODULUS.subtract(&y);
                let (_, borrow) = p_y.informed_subtract(&y);
                let recovered_y = if borrow == 0 { y } else { p_y };
                AffinePoint {
                    x,
                    y: recovered_y.as_montgomery(),
                    infinity: Choice::from(0),
                }
            })
        })
    }
}

impl FromEncodedPoint<NistP256> for AffinePoint {
    /// Attempts to parse the given [`EncodedPoint`] as an SEC1-encoded [`AffinePoint`].
    ///
    /// # Returns
    ///
    /// `None` value if `encoded_point` is not on the secp256r1 curve.
    fn from_encoded_point(encoded_point: &EncodedPoint) -> CtOption<Self> {
        match encoded_point.coordinates() {
            sec1::Coordinates::Identity => CtOption::new(Self::identity(), 1.into()),
            sec1::Coordinates::Compact { x } => AffinePoint::decompact(x),
            sec1::Coordinates::Compressed { x, y_is_odd } => {
                AffinePoint::decompress(x, Choice::from(y_is_odd as u8))
            }
            sec1::Coordinates::Uncompressed { x, y } => {
                let x = FieldElement::from_bytes(x);
                let y = FieldElement::from_bytes(y);

                x.and_then(|x| {
                    y.and_then(|y| {
                        // Check that the point is on the curve
                        let lhs = y * &y;
                        let rhs = x * &x * &x + &(CURVE_EQUATION_A * &x) + &CURVE_EQUATION_B;
                        let point = AffinePoint {
                            x,
                            y,
                            infinity: Choice::from(0),
                        };
                        CtOption::new(point, lhs.ct_eq(&rhs))
                    })
                })
            }
        }
    }
}

impl ToEncodedPoint<NistP256> for AffinePoint {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        EncodedPoint::conditional_select(
            &EncodedPoint::from_affine_coordinates(
                &self.x.to_bytes(),
                &self.y.to_bytes(),
                compress,
            ),
            &EncodedPoint::identity(),
            self.infinity,
        )
    }
}

impl ToCompactEncodedPoint<NistP256> for AffinePoint {
    /// Serialize this value as a  SEC1 compact [`EncodedPoint`]
    fn to_compact_encoded_point(&self) -> Option<EncodedPoint> {
        // Convert to canonical form for comparisons
        let y = self.y.as_canonical();
        let (p_y, borrow) = MODULUS.informed_subtract(&y);
        assert_eq!(borrow, 0);
        let (_, borrow) = p_y.informed_subtract(&y);
        if borrow != 0 {
            return None;
        }
        // Reuse the CompressedPoint type since it's the same size as a compact point
        let mut bytes = CompressedPoint::default();
        bytes[0] = Tag::Compact.into();
        bytes[1..(<NistP256 as Curve>::UInt::BYTE_SIZE + 1)].copy_from_slice(&self.x.to_bytes());
        Some(EncodedPoint::from_bytes(bytes).expect("compact key"))
    }
}

impl TryFrom<EncodedPoint> for AffinePoint {
    type Error = Error;

    fn try_from(point: EncodedPoint) -> Result<AffinePoint> {
        AffinePoint::try_from(&point)
    }
}

impl TryFrom<&EncodedPoint> for AffinePoint {
    type Error = Error;

    fn try_from(point: &EncodedPoint) -> Result<AffinePoint> {
        Option::from(AffinePoint::from_encoded_point(point)).ok_or(Error)
    }
}

impl From<AffinePoint> for EncodedPoint {
    /// Returns the SEC1 compressed encoding of this point.
    fn from(affine_point: AffinePoint) -> EncodedPoint {
        affine_point.to_encoded_point(false)
    }
}

impl Mul<Scalar> for AffinePoint {
    type Output = ProjectivePoint;

    fn mul(self, scalar: Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self) * scalar
    }
}

impl Mul<&Scalar> for AffinePoint {
    type Output = ProjectivePoint;

    fn mul(self, scalar: &Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self) * scalar
    }
}

impl Neg for AffinePoint {
    type Output = AffinePoint;

    fn neg(self) -> Self::Output {
        AffinePoint {
            x: self.x,
            y: -self.y,
            infinity: self.infinity,
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for AffinePoint {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.to_encoded_point(true).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> Deserialize<'de> for AffinePoint {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        EncodedPoint::deserialize(deserializer)?
            .try_into()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::AffinePoint;
    use crate::EncodedPoint;
    use elliptic_curve::{
        group::{prime::PrimeCurveAffine, GroupEncoding},
        sec1::{FromEncodedPoint, ToCompactEncodedPoint, ToEncodedPoint},
    };
    use hex_literal::hex;

    const UNCOMPRESSED_BASEPOINT: &[u8] = &hex!(
        "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
         4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
    );

    const COMPRESSED_BASEPOINT: &[u8] =
        &hex!("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");

    // Tag compact with 05 as the first byte, to trigger tag based compaction
    const COMPACT_BASEPOINT: &[u8] =
        &hex!("058e38fc4ffe677662dde8e1a63fbcd45959d2a4c3004d27e98c4fedf2d0c14c01");

    // Tag uncompact basepoint with 04 as the first byte as it is uncompressed
    const UNCOMPACT_BASEPOINT: &[u8] = &hex!(
        "048e38fc4ffe677662dde8e1a63fbcd45959d2a4c3004d27e98c4fedf2d0c14c0
        13ca9d8667de0c07aa71d98b3c8065d2e97ab7bb9cb8776bcc0577a7ac58acd4e"
    );

    #[test]
    fn uncompressed_round_trip() {
        let pubkey = EncodedPoint::from_bytes(UNCOMPRESSED_BASEPOINT).unwrap();
        let point = AffinePoint::from_encoded_point(&pubkey).unwrap();
        assert_eq!(point, AffinePoint::generator());

        let res: EncodedPoint = point.into();
        assert_eq!(res, pubkey);
    }

    #[test]
    fn compressed_round_trip() {
        let pubkey = EncodedPoint::from_bytes(COMPRESSED_BASEPOINT).unwrap();
        let point = AffinePoint::from_encoded_point(&pubkey).unwrap();
        assert_eq!(point, AffinePoint::generator());

        let res: EncodedPoint = point.to_encoded_point(true);
        assert_eq!(res, pubkey);
    }

    #[test]
    fn uncompressed_to_compressed() {
        let encoded = EncodedPoint::from_bytes(UNCOMPRESSED_BASEPOINT).unwrap();

        let res = AffinePoint::from_encoded_point(&encoded)
            .unwrap()
            .to_encoded_point(true);

        assert_eq!(res.as_bytes(), COMPRESSED_BASEPOINT);
    }

    #[test]
    fn compressed_to_uncompressed() {
        let encoded = EncodedPoint::from_bytes(COMPRESSED_BASEPOINT).unwrap();

        let res = AffinePoint::from_encoded_point(&encoded)
            .unwrap()
            .to_encoded_point(false);

        assert_eq!(res.as_bytes(), UNCOMPRESSED_BASEPOINT);
    }

    #[test]
    fn affine_negation() {
        let basepoint = AffinePoint::generator();
        assert_eq!(-(-basepoint), basepoint);
    }

    #[test]
    fn compact_round_trip() {
        let pubkey = EncodedPoint::from_bytes(COMPACT_BASEPOINT).unwrap();
        assert!(pubkey.is_compact());

        let point = AffinePoint::from_encoded_point(&pubkey).unwrap();
        let res = point.to_compact_encoded_point().unwrap();
        assert_eq!(res, pubkey)
    }

    #[test]
    fn uncompact_to_compact() {
        let pubkey = EncodedPoint::from_bytes(UNCOMPACT_BASEPOINT).unwrap();
        assert_eq!(false, pubkey.is_compact());

        let point = AffinePoint::from_encoded_point(&pubkey).unwrap();
        let res = point.to_compact_encoded_point().unwrap();
        assert_eq!(res.as_bytes(), COMPACT_BASEPOINT)
    }

    #[test]
    fn compact_to_uncompact() {
        let pubkey = EncodedPoint::from_bytes(COMPACT_BASEPOINT).unwrap();
        assert!(pubkey.is_compact());

        let point = AffinePoint::from_encoded_point(&pubkey).unwrap();
        // Do not do compact encoding as we want to keep uncompressed point
        let res = point.to_encoded_point(false);
        assert_eq!(res.as_bytes(), UNCOMPACT_BASEPOINT);
    }

    #[test]
    fn identity_encoding() {
        // This is technically an invalid SEC1 encoding, but is preferable to panicking.
        assert_eq!([0; 33], AffinePoint::identity().to_bytes().as_slice());
        assert!(bool::from(
            AffinePoint::from_bytes(&AffinePoint::identity().to_bytes())
                .unwrap()
                .is_identity()
        ))
    }
}
