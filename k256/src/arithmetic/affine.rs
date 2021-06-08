//! Affine points

use super::{FieldElement, ProjectivePoint, CURVE_EQUATION_B};
use crate::{CompressedPoint, EncodedPoint, FieldBytes, Scalar, Secp256k1};
use core::ops::{Mul, Neg};
use elliptic_curve::{
    generic_array::arr,
    group::{prime::PrimeCurveAffine, GroupEncoding},
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    weierstrass::DecompressPoint,
    AffineArithmetic,
};

#[cfg(feature = "zeroize")]
use elliptic_curve::zeroize::Zeroize;

impl AffineArithmetic for Secp256k1 {
    type AffinePoint = AffinePoint;
}

/// A point on the secp256k1 curve in affine coordinates.
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
    fn identity() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
            infinity: Choice::from(1),
        }
    }

    /// Returns the base point of SECP256k1.
    fn generator() -> Self {
        // SECP256k1 basepoint in affine coordinates:
        // x = 79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798
        // y = 483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8
        AffinePoint {
            x: FieldElement::from_bytes(&arr![u8;
                0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
                0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
                0x16, 0xf8, 0x17, 0x98
            ])
            .unwrap(),
            y: FieldElement::from_bytes(&arr![u8;
                0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11,
                0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f,
                0xfb, 0x10, 0xd4, 0xb8
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
        (self.x.negate(1) + &other.x).normalizes_to_zero()
            & (self.y.negate(1) + &other.y).normalizes_to_zero()
            & self.infinity.ct_eq(&other.infinity)
    }
}

impl Default for AffinePoint {
    fn default() -> Self {
        Self::identity()
    }
}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &AffinePoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AffinePoint {}

impl AffinePoint {
    /// Decode this point from a SEC1-encoded point.
    pub(crate) fn decode(encoded_point: &EncodedPoint) -> CtOption<Self> {
        match encoded_point.coordinates() {
            sec1::Coordinates::Identity => CtOption::new(Self::identity(), 1.into()),
            sec1::Coordinates::Compact { .. } => {
                // TODO(tarcieri): add decompaction support
                CtOption::new(Self::default(), 0.into())
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
                        let lhs = (y * &y).negate(1);
                        let rhs = x * &x * &x + &CURVE_EQUATION_B;
                        let point = AffinePoint {
                            x,
                            y,
                            infinity: Choice::from(0),
                        };
                        CtOption::new(point, (lhs + &rhs).normalizes_to_zero())
                    })
                })
            }
        }
    }
}

impl DecompressPoint<Secp256k1> for AffinePoint {
    fn decompress(x_bytes: &FieldBytes, y_is_odd: Choice) -> CtOption<Self> {
        FieldElement::from_bytes(x_bytes).and_then(|x| {
            let alpha = (x * &x * &x) + &CURVE_EQUATION_B;
            let beta = alpha.sqrt();

            beta.map(|beta| {
                let y = FieldElement::conditional_select(
                    &beta.negate(1),
                    &beta,
                    beta.normalize().is_odd().ct_eq(&y_is_odd),
                );

                Self {
                    x,
                    y: y.normalize(),
                    infinity: Choice::from(0),
                }
            })
        })
    }
}

impl GroupEncoding for AffinePoint {
    type Repr = CompressedPoint;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let tag = bytes[0];
        let y_is_odd = tag.ct_eq(&sec1::Tag::CompressedOddY.into());
        let is_compressed_point = y_is_odd | tag.ct_eq(&sec1::Tag::CompressedEvenY.into());
        Self::decompress(FieldBytes::from_slice(&bytes[1..]), y_is_odd)
            .and_then(|point| CtOption::new(point, is_compressed_point))
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        CompressedPoint::clone_from_slice(self.to_encoded_point(true).as_bytes())
    }
}

impl FromEncodedPoint<Secp256k1> for AffinePoint {
    /// Attempts to parse the given [`EncodedPoint`] as an SEC1-encoded [`AffinePoint`].
    ///
    /// # Returns
    ///
    /// `None` value if `encoded_point` is not on the secp256k1 curve.
    fn from_encoded_point(encoded_point: &EncodedPoint) -> Option<Self> {
        Self::decode(encoded_point).into()
    }
}

impl ToEncodedPoint<Secp256k1> for AffinePoint {
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

impl From<AffinePoint> for EncodedPoint {
    /// Returns the SEC1 compressed encoding of this point.
    fn from(affine_point: AffinePoint) -> EncodedPoint {
        affine_point.to_encoded_point(true)
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
            y: self.y.negate(1).normalize_weak(),
            infinity: self.infinity,
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for AffinePoint {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::AffinePoint;
    use crate::EncodedPoint;
    use elliptic_curve::{
        group::prime::PrimeCurveAffine,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    };
    use hex_literal::hex;

    const UNCOMPRESSED_BASEPOINT: &[u8] = &hex!(
        "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
         483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
    );
    const COMPRESSED_BASEPOINT: &[u8] =
        &hex!("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");

    #[test]
    fn uncompressed_round_trip() {
        let pubkey = EncodedPoint::from_bytes(UNCOMPRESSED_BASEPOINT).unwrap();
        let res: EncodedPoint = AffinePoint::from_encoded_point(&pubkey)
            .unwrap()
            .to_encoded_point(false);

        assert_eq!(res, pubkey);
    }

    #[test]
    fn compressed_round_trip() {
        let pubkey = EncodedPoint::from_bytes(COMPRESSED_BASEPOINT).unwrap();
        let res: EncodedPoint = AffinePoint::from_encoded_point(&pubkey)
            .unwrap()
            .to_encoded_point(true);

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
    fn decompress() {
        let encoded = EncodedPoint::from_bytes(COMPRESSED_BASEPOINT).unwrap();
        let decompressed = encoded.decompress().unwrap();
        assert_eq!(decompressed.as_bytes(), UNCOMPRESSED_BASEPOINT);
    }

    #[test]
    fn affine_negation() {
        let basepoint = AffinePoint::generator();
        assert_eq!((-(-basepoint)), basepoint);
    }
}
