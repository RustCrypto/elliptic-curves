//! Affine points on the NIST P-384 elliptic curve.

use super::{FieldElement, CURVE_EQUATION_A, CURVE_EQUATION_B, MODULUS};
use crate::{CompressedPoint, EncodedPoint, FieldBytes, NistP384};
use core::ops::Neg;
use elliptic_curve::{
    generic_array::arr,
    group::GroupEncoding,
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    AffineArithmetic, AffineXCoordinate, DecompressPoint, Error, Result,
};

#[cfg(feature = "serde")]
use elliptic_curve::serde::{de, ser, Deserialize, Serialize};

impl AffineArithmetic for NistP384 {
    type AffinePoint = AffinePoint;
}

/// NIST P-384 (secp384r1) curve point expressed in affine coordinates.
///
/// # `serde` support
///
/// When the `serde` feature of this crate is enabled, the `Serialize` and
/// `Deserialize` traits are impl'd for this type.
///
/// The serialization uses the [SEC1] `Elliptic-Curve-Point-to-Octet-String`
/// encoding, serialized as binary.
///
/// When serialized with a text-based format, the SEC1 representation is
/// subsequently hex encoded.
///
/// [SEC1]: https://www.secg.org/sec1-v2.pdf
#[derive(Clone, Copy, Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "broken-arithmetic-do-not-use")))]
pub struct AffinePoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(super) infinity: Choice,
}

impl AffinePoint {
    /// Returns the identity of the group: the point at infinity.
    pub fn identity() -> AffinePoint {
        Self {
            x: FieldElement::ZERO,
            y: FieldElement::ZERO,
            infinity: Choice::from(1),
        }
    }

    /// Returns the base point of P-384.
    ///
    /// Defined in FIPS 186-4 § D.1.2.4:
    ///
    /// ```text
    /// Gₓ = aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98
    ///      59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7
    /// Gᵧ = 3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c
    ///      e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f
    /// ```
    pub fn generator() -> AffinePoint {
        AffinePoint {
            x: FieldElement::from_bytes(&arr![u8;
                0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e,
                0xf3, 0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
                0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d,
                0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7
            ])
            .unwrap(),
            y: FieldElement::from_bytes(&arr![u8;
                0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf,
                0x92, 0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
                0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce,
                0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f
            ])
            .unwrap(),
            infinity: Choice::from(0),
        }
    }

    /// Is this point the identity point?
    pub fn is_identity(&self) -> Choice {
        self.infinity
    }
}

impl AffineXCoordinate<NistP384> for AffinePoint {
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

impl DecompressPoint<NistP384> for AffinePoint {
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

impl FromEncodedPoint<NistP384> for AffinePoint {
    /// Attempts to parse the given [`EncodedPoint`] as an SEC1-encoded [`AffinePoint`].
    ///
    /// # Returns
    ///
    /// `None` value if `encoded_point` is not on the secp384r1 curve.
    fn from_encoded_point(encoded_point: &EncodedPoint) -> CtOption<Self> {
        match encoded_point.coordinates() {
            sec1::Coordinates::Identity => CtOption::new(Self::identity(), 1.into()),
            sec1::Coordinates::Compact { .. } => {
                // TODO(tarcieri): point decompaction support
                CtOption::new(Self::identity(), Choice::from(0))
            }
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

impl ToEncodedPoint<NistP384> for AffinePoint {
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
        group::GroupEncoding,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    };
    use hex_literal::hex;

    const UNCOMPRESSED_BASEPOINT: &[u8] = &hex!(
        "04 aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98
         59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7
         3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c
         e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f"
    );

    const COMPRESSED_BASEPOINT: &[u8] = &hex!(
        "03 aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98
         59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7"
    );

    #[test]
    #[ignore]
    fn uncompressed_round_trip() {
        let pubkey = EncodedPoint::from_bytes(UNCOMPRESSED_BASEPOINT).unwrap();
        let point = AffinePoint::from_encoded_point(&pubkey).unwrap();
        assert_eq!(point, AffinePoint::generator());

        let res: EncodedPoint = point.into();
        assert_eq!(res, pubkey);
    }

    #[test]
    #[ignore]
    fn compressed_round_trip() {
        let pubkey = EncodedPoint::from_bytes(COMPRESSED_BASEPOINT).unwrap();
        let point = AffinePoint::from_encoded_point(&pubkey).unwrap();
        assert_eq!(point, AffinePoint::generator());

        let res: EncodedPoint = point.to_encoded_point(true);
        assert_eq!(res, pubkey);
    }

    #[test]
    #[ignore]
    fn uncompressed_to_compressed() {
        let encoded = EncodedPoint::from_bytes(UNCOMPRESSED_BASEPOINT).unwrap();

        let res = AffinePoint::from_encoded_point(&encoded)
            .unwrap()
            .to_encoded_point(true);

        assert_eq!(res.as_bytes(), COMPRESSED_BASEPOINT);
    }

    #[test]
    #[ignore]
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
    fn identity_encoding() {
        // This is technically an invalid SEC1 encoding, but is preferable to panicking.
        assert_eq!([0; 49], AffinePoint::identity().to_bytes().as_slice());
        assert!(bool::from(
            AffinePoint::from_bytes(&AffinePoint::identity().to_bytes())
                .unwrap()
                .is_identity()
        ))
    }
}
